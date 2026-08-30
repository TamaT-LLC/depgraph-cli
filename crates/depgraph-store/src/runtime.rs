use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use depgraph_protocol::stable_id_from_value;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    CoverageRecord, DiagnosticRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord,
    ProfileRecord, SiteRecord, SnapshotSource, Store, canonical_effective_input_id,
    completed_snapshot_identity, create_completed_snapshot, declared_effective_input_id,
    declared_parent_profile_id, promote_completed_snapshot, refresh_profile_matrix,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeSessionRecord {
    pub id: String,
    pub base_snapshot_id: String,
    pub source_session_id: String,
    pub schema_version: String,
    pub status: String,
    pub trace_digest: String,
    pub profile_id: String,
    pub parent_profile_id: Option<String>,
    pub profile_status: String,
    pub profile_reason: Option<String>,
    pub profile: ProfileRecord,
    pub environment: Value,
    pub redaction: Value,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub first_observed_at: String,
    pub last_observed_at: String,
    pub event_count: u64,
    pub observation_count: u64,
    pub resolved_targets: u64,
    pub external_targets: u64,
    pub unresolved_targets: u64,
    pub redacted_values: u64,
    pub coverage: CoverageRecord,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeSessionDelta {
    pub session: RuntimeSessionRecord,
    pub nodes: Vec<NodeRecord>,
    pub sites: Vec<SiteRecord>,
    pub edges: Vec<EdgeRecord>,
    pub evidence: Vec<EvidenceRecord>,
    pub diagnostics: Vec<DiagnosticRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeImportResult {
    pub import_id: String,
    pub session_id: String,
    pub snapshot_id: String,
    pub status: String,
    pub deduplicated: bool,
}

/// Complete durable binding used by operation-owned runtime import recovery.
pub struct RuntimeImportRecoveryIdentity<'a> {
    import_id: &'a str,
    session_id: &'a str,
    snapshot_id: &'a str,
    parent_snapshot_id: &'a str,
    trace_digest: Option<&'a str>,
    status: &'a str,
    operation_id: &'a str,
}

impl<'a> RuntimeImportRecoveryIdentity<'a> {
    #[must_use]
    pub const fn new(
        import_id: &'a str,
        session_id: &'a str,
        snapshot_id: &'a str,
        parent_snapshot_id: &'a str,
        trace_digest: &'a str,
        status: &'a str,
        operation_id: &'a str,
    ) -> Self {
        Self {
            import_id,
            session_id,
            snapshot_id,
            parent_snapshot_id,
            trace_digest: Some(trace_digest),
            status,
            operation_id,
        }
    }

    /// Bind recovery to the identities in a validated immutable completion
    /// outcome when legacy normalized input did not retain a trace digest. The
    /// selected stored session must reproduce its deterministic session ID from
    /// its source-session ID and trace digest before it can be promoted.
    #[must_use]
    pub const fn from_validated_outcome(
        import_id: &'a str,
        session_id: &'a str,
        snapshot_id: &'a str,
        parent_snapshot_id: &'a str,
        status: &'a str,
        operation_id: &'a str,
    ) -> Self {
        Self {
            import_id,
            session_id,
            snapshot_id,
            parent_snapshot_id,
            trace_digest: None,
            status,
            operation_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRuntimeImport {
    result: RuntimeImportResult,
    pending: bool,
}

impl PreparedRuntimeImport {
    #[must_use]
    pub const fn result(&self) -> &RuntimeImportResult {
        &self.result
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.pending
    }

    #[must_use]
    pub fn into_result(self) -> RuntimeImportResult {
        self.result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeImportMode {
    Immediate,
    Deferred,
}

#[derive(Clone, Copy)]
struct RuntimeImportRecoveryBinding<'a> {
    operation_id: &'a str,
    parent_snapshot_id: &'a str,
    trace_digest: Option<&'a str>,
    status: &'a str,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEdgeContext {
    pub session_ids: Vec<String>,
    pub source_session_ids: Vec<String>,
    pub environment_names: Vec<String>,
    pub runtimes: Vec<String>,
    pub regions: Vec<String>,
    pub observation_count: u64,
    pub first_observed_at: Option<String>,
    pub last_observed_at: Option<String>,
}

impl Store {
    /// Atomically publishes one validated runtime session as a new immutable
    /// completed snapshot. The graph rows and current pointer are committed in
    /// the same transaction, so a failed import cannot expose a partial
    /// session.
    pub fn import_runtime_session(
        &mut self,
        base_snapshot_id: &str,
        delta: RuntimeSessionDelta,
    ) -> Result<RuntimeImportResult> {
        let prepared = self.import_runtime_session_with_mode(
            base_snapshot_id,
            delta,
            RuntimeImportMode::Immediate,
            None,
        )?;
        if prepared.is_pending() {
            bail!("immediate runtime import was not promoted");
        }
        Ok(prepared.into_result())
    }

    /// Validate and durably stage one runtime session without creating or
    /// publishing a completed snapshot. The caller must retain the external
    /// store-writer lock until it either promotes or cancels this preparation.
    pub fn prepare_runtime_session_import(
        &mut self,
        base_snapshot_id: &str,
        delta: RuntimeSessionDelta,
        operation_id: &str,
    ) -> Result<PreparedRuntimeImport> {
        self.import_runtime_session_with_mode(
            base_snapshot_id,
            delta,
            RuntimeImportMode::Deferred,
            Some(operation_id),
        )
    }

    fn import_runtime_session_with_mode(
        &mut self,
        base_snapshot_id: &str,
        mut delta: RuntimeSessionDelta,
        mode: RuntimeImportMode,
        operation_id: Option<&str>,
    ) -> Result<PreparedRuntimeImport> {
        match (mode, operation_id) {
            (RuntimeImportMode::Immediate, None) => {}
            (RuntimeImportMode::Deferred, Some(operation_id))
                if valid_runtime_import_operation_id(operation_id) => {}
            (RuntimeImportMode::Deferred, Some(_)) => {
                bail!("runtime import operation identity is invalid");
            }
            _ => bail!("runtime import staging ownership is invalid"),
        }
        normalize_runtime_delta(&mut delta);
        if delta.session.base_snapshot_id != base_snapshot_id {
            bail!("runtime session base snapshot does not match the selected snapshot");
        }
        let base_record = self
            .completed_snapshot(base_snapshot_id)?
            .with_context(|| format!("completed snapshot {base_snapshot_id} was not found"))?;
        if !self.verify_snapshot_integrity(base_snapshot_id)?.valid {
            bail!("runtime session base snapshot {base_snapshot_id} failed integrity validation");
        }
        if base_record
            .runtime_session_ids
            .binary_search(&delta.session.id)
            .is_ok()
        {
            let existing = load_runtime_session_record(&self.connection, &delta.session.id)?
                .with_context(|| {
                    format!(
                        "runtime session {} referenced by snapshot was not found",
                        delta.session.id
                    )
                })?;
            if existing.trace_digest != delta.session.trace_digest
                || existing.source_session_id != delta.session.source_session_id
            {
                bail!(
                    "runtime session identity collision for {}",
                    delta.session.id
                );
            }
            return Ok(PreparedRuntimeImport {
                result: RuntimeImportResult {
                    import_id: base_record
                        .runtime_import_id
                        .unwrap_or_else(|| "runtime-import:deduplicated".to_owned()),
                    session_id: delta.session.id,
                    snapshot_id: base_snapshot_id.to_owned(),
                    status: existing.status,
                    deduplicated: true,
                },
                pending: false,
            });
        }
        let base = self.load_completed_snapshot(base_snapshot_id)?;
        validate_runtime_union(&base, &delta)?;

        let mut runtime_session_ids = base_record.runtime_session_ids.clone();
        runtime_session_ids.push(delta.session.id.clone());
        runtime_session_ids.sort();
        runtime_session_ids.dedup();
        let import_id =
            runtime_import_identity(base_snapshot_id, &delta.session.id, &runtime_session_ids);
        if let Some((existing_parent, existing_session, status, result_snapshot_id)) = self
            .connection
            .query_row(
                "SELECT parent_snapshot_id, session_id, status, result_snapshot_id
                   FROM runtime_imports WHERE id=?1",
                [&import_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?
        {
            if existing_parent != base_snapshot_id || existing_session != delta.session.id {
                bail!("runtime import identity collision for {import_id}");
            }
            let stored_delta = load_runtime_delta(&self.connection, &existing_session)?;
            let mut comparable_stored_delta = stored_delta.clone();
            // Import preparation time is audit metadata, not trace identity.
            // Every other stored field must reproduce exactly on replay.
            comparable_stored_delta.session.created_at = delta.session.created_at.clone();
            if comparable_stored_delta != delta {
                bail!("runtime import replay delta does not match staged evidence");
            }
            match status.as_str() {
                "completed" => {
                    let snapshot_id = result_snapshot_id
                        .context("completed runtime import has no result snapshot")?;
                    let snapshot = self
                        .completed_snapshot(&snapshot_id)?
                        .context("completed runtime import result snapshot was not found")?;
                    if snapshot.parent_snapshot_id.as_deref() != Some(base_snapshot_id)
                        || snapshot.runtime_import_id.as_deref() != Some(import_id.as_str())
                        || !snapshot.runtime_session_ids.contains(&existing_session)
                        || !self.verify_snapshot_integrity(&snapshot_id)?.valid
                    {
                        bail!("completed runtime import result snapshot identity does not match");
                    }
                    clear_runtime_import_operation_owners(&mut self.connection, &import_id)?;
                    return Ok(PreparedRuntimeImport {
                        result: RuntimeImportResult {
                            import_id,
                            session_id: existing_session,
                            snapshot_id,
                            status: stored_delta.session.status,
                            deduplicated: true,
                        },
                        pending: false,
                    });
                }
                "staging" if result_snapshot_id.is_none() => {
                    let expected_snapshot_id = completed_snapshot_identity(
                        &self.connection,
                        &base_record.scan_id,
                        base_record.build_attempt_id.as_deref(),
                        &runtime_session_ids,
                        Some(base_snapshot_id),
                        base_record.source_revision.as_deref(),
                    )?
                    .0;
                    if mode == RuntimeImportMode::Immediate {
                        let result = self.promote_staged_runtime_session_import(
                            &import_id,
                            &existing_session,
                            &expected_snapshot_id,
                            None,
                        )?;
                        return Ok(PreparedRuntimeImport {
                            result,
                            pending: false,
                        });
                    }
                    attach_runtime_import_operation_owner(
                        &mut self.connection,
                        &import_id,
                        base_snapshot_id,
                        &existing_session,
                        operation_id.context("deferred runtime import has no operation owner")?,
                    )?;
                    return Ok(PreparedRuntimeImport {
                        result: RuntimeImportResult {
                            import_id,
                            session_id: existing_session,
                            snapshot_id: expected_snapshot_id,
                            status: stored_delta.session.status,
                            deduplicated: false,
                        },
                        pending: true,
                    });
                }
                _ => bail!("runtime import replay found an invalid operation state"),
            }
        }
        let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let tx = self.connection.transaction()?;
        store_runtime_session(&tx, &delta)?;
        tx.execute(
            "INSERT INTO runtime_imports(
                id, parent_snapshot_id, session_id, status, created_at
             ) VALUES (?1, ?2, ?3, 'staging', ?4)",
            params![import_id, base_snapshot_id, delta.session.id, created_at],
        )?;
        if let Some(operation_id) = operation_id {
            tx.execute(
                "INSERT INTO runtime_import_operation_owners(
                    import_id, operation_id, created_at
                 ) VALUES (?1, ?2, ?3)",
                params![import_id, operation_id, created_at],
            )?;
        }
        // For a deferred import, parent_snapshot_id is also the durable
        // compare-and-publish identity. It is captured with the staged session
        // in this transaction and checked again in the completion transaction.
        let snapshot_id = match mode {
            RuntimeImportMode::Immediate => {
                let snapshot_id = create_completed_snapshot(
                    &tx,
                    SnapshotSource {
                        source_kind: "runtime",
                        source_attempt_id: &import_id,
                        scan_id: &base_record.scan_id,
                        build_attempt_id: base_record.build_attempt_id.as_deref(),
                        runtime_import_id: Some(&import_id),
                        runtime_session_ids: &runtime_session_ids,
                        parent_snapshot_id: Some(base_snapshot_id),
                        source_revision: base_record.source_revision.as_deref(),
                        created_at: &created_at,
                    },
                )?;
                tx.execute(
                    "UPDATE runtime_imports
                        SET status='completed', result_snapshot_id=?2, completed_at=?3
                      WHERE id=?1 AND status='staging'",
                    params![import_id, snapshot_id, created_at],
                )?;
                promote_runtime_snapshot_if_parent_is_current(&tx, base_snapshot_id, &snapshot_id)?;
                snapshot_id
            }
            RuntimeImportMode::Deferred => {
                completed_snapshot_identity(
                    &tx,
                    &base_record.scan_id,
                    base_record.build_attempt_id.as_deref(),
                    &runtime_session_ids,
                    Some(base_snapshot_id),
                    base_record.source_revision.as_deref(),
                )?
                .0
            }
        };
        tx.commit()?;
        Ok(PreparedRuntimeImport {
            result: RuntimeImportResult {
                import_id,
                session_id: delta.session.id,
                snapshot_id,
                status: delta.session.status,
                deduplicated: false,
            },
            pending: matches!(mode, RuntimeImportMode::Deferred),
        })
    }

    /// Atomically turn a staged runtime import into a completed immutable
    /// snapshot and publish it only while its parent is still current.
    /// Replaying an already-completed import verifies identity without moving
    /// current backwards.
    pub fn promote_runtime_session_import(
        &mut self,
        import_id: &str,
        expected_session_id: &str,
        expected_snapshot_id: &str,
    ) -> Result<RuntimeImportResult> {
        self.promote_staged_runtime_session_import(
            import_id,
            expected_session_id,
            expected_snapshot_id,
            None,
        )
    }

    /// Recover a deferred promotion only when the complete durable operation
    /// binding matches the staged import. A pre-v16 staging row may instead be
    /// owned by the one deterministic migration sentinel for this exact
    /// import; caller-supplied operation IDs can never use that reserved form.
    pub fn recover_runtime_session_import_for_operation(
        &mut self,
        recovery: &RuntimeImportRecoveryIdentity<'_>,
    ) -> Result<RuntimeImportResult> {
        reject_reserved_runtime_import_operation_id(recovery.operation_id)?;
        self.promote_staged_runtime_session_import(
            recovery.import_id,
            recovery.session_id,
            recovery.snapshot_id,
            Some(RuntimeImportRecoveryBinding {
                operation_id: recovery.operation_id,
                parent_snapshot_id: recovery.parent_snapshot_id,
                trace_digest: recovery.trace_digest,
                status: recovery.status,
            }),
        )
    }

    fn promote_staged_runtime_session_import(
        &mut self,
        import_id: &str,
        expected_session_id: &str,
        expected_snapshot_id: &str,
        recovery: Option<RuntimeImportRecoveryBinding<'_>>,
    ) -> Result<RuntimeImportResult> {
        let (parent_snapshot_id, session_id, import_status, result_snapshot_id) =
            self.connection.query_row(
                "SELECT parent_snapshot_id, session_id, status, result_snapshot_id
                   FROM runtime_imports WHERE id=?1",
                [import_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )?;
        if session_id != expected_session_id {
            bail!("runtime import session identity does not match");
        }
        let session = load_runtime_session_record(&self.connection, &session_id)?
            .context("runtime import session was not found")?;
        if let Some(recovery) = recovery
            && (parent_snapshot_id != recovery.parent_snapshot_id
                || session.base_snapshot_id != recovery.parent_snapshot_id
                || !runtime_recovery_trace_matches(
                    &session.id,
                    &session.source_session_id,
                    &session.trace_digest,
                    recovery.trace_digest,
                )
                || session.status != recovery.status)
        {
            bail!("runtime import durable input identity does not match");
        }
        let base_record = self
            .completed_snapshot(&parent_snapshot_id)?
            .context("runtime import parent snapshot was not found")?;
        let mut expected_runtime_session_ids = base_record.runtime_session_ids.clone();
        expected_runtime_session_ids.push(session_id.clone());
        expected_runtime_session_ids.sort();
        expected_runtime_session_ids.dedup();
        if runtime_import_identity(
            &parent_snapshot_id,
            &session_id,
            &expected_runtime_session_ids,
        ) != import_id
        {
            bail!("runtime import identity does not match durable input");
        }
        if import_status == "completed" {
            if result_snapshot_id.as_deref() != Some(expected_snapshot_id) {
                bail!("completed runtime import snapshot identity does not match");
            }
            let snapshot = self
                .completed_snapshot(expected_snapshot_id)?
                .context("completed runtime import result snapshot was not found")?;
            if snapshot.parent_snapshot_id.as_deref() != Some(parent_snapshot_id.as_str())
                || snapshot.runtime_import_id.as_deref() != Some(import_id)
                || !snapshot.runtime_session_ids.contains(&session_id)
                || !self.verify_snapshot_integrity(expected_snapshot_id)?.valid
            {
                bail!("completed runtime import evidence failed integrity validation");
            }
            clear_runtime_import_operation_owners(&mut self.connection, import_id)?;
            return Ok(RuntimeImportResult {
                import_id: import_id.to_owned(),
                session_id,
                snapshot_id: expected_snapshot_id.to_owned(),
                status: session.status,
                deduplicated: false,
            });
        }
        if import_status != "staging" || result_snapshot_id.is_some() {
            bail!("runtime import is not promotable");
        }
        if !self.verify_snapshot_integrity(&parent_snapshot_id)?.valid {
            bail!("runtime import parent snapshot failed integrity validation");
        }
        let delta = load_runtime_delta(&self.connection, &session_id)?;
        let base = self.load_completed_snapshot(&parent_snapshot_id)?;
        validate_runtime_union(&base, &delta)?;
        let mut runtime_session_ids = base_record.runtime_session_ids.clone();
        runtime_session_ids.push(session_id.clone());
        runtime_session_ids.sort();
        runtime_session_ids.dedup();
        let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let tx = self.connection.transaction()?;
        if let Some(recovery) = recovery {
            let (
                transaction_parent,
                transaction_session,
                transaction_import_status,
                transaction_result_snapshot,
                transaction_session_parent,
                transaction_source_session,
                transaction_trace_digest,
                transaction_session_status,
            ) = tx.query_row(
                "SELECT import.parent_snapshot_id, import.session_id, import.status,
                        import.result_snapshot_id, session.base_snapshot_id,
                        session.source_session_id, session.trace_digest, session.status
                   FROM runtime_imports AS import
                   JOIN runtime_sessions AS session ON session.id=import.session_id
                  WHERE import.id=?1",
                [import_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )?;
            if transaction_parent != recovery.parent_snapshot_id
                || transaction_session != expected_session_id
                || transaction_import_status != "staging"
                || transaction_result_snapshot.is_some()
                || transaction_session_parent != recovery.parent_snapshot_id
                || transaction_session_status != recovery.status
                || !runtime_recovery_trace_matches(
                    &transaction_session,
                    &transaction_source_session,
                    &transaction_trace_digest,
                    recovery.trace_digest,
                )
            {
                bail!("runtime import recovery identity changed before promotion");
            }
            let operation_owned: bool = tx.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM runtime_import_operation_owners
                      WHERE import_id=?1 AND operation_id=?2
                 )",
                params![import_id, recovery.operation_id],
                |row| row.get(0),
            )?;
            let legacy_owner = crate::legacy_runtime_import_owner_id(import_id);
            let legacy_owned: bool = tx.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM runtime_import_operation_owners
                      WHERE import_id=?1 AND operation_id=?2
                 )",
                params![import_id, legacy_owner],
                |row| row.get(0),
            )?;
            if !operation_owned && !legacy_owned {
                bail!("runtime import completion operation does not own staging");
            }
        }
        let snapshot_id = create_completed_snapshot(
            &tx,
            SnapshotSource {
                source_kind: "runtime",
                source_attempt_id: import_id,
                scan_id: &base_record.scan_id,
                build_attempt_id: base_record.build_attempt_id.as_deref(),
                runtime_import_id: Some(import_id),
                runtime_session_ids: &runtime_session_ids,
                parent_snapshot_id: Some(&parent_snapshot_id),
                source_revision: base_record.source_revision.as_deref(),
                created_at: &completed_at,
            },
        )?;
        if snapshot_id != expected_snapshot_id {
            bail!("runtime import prospective snapshot identity changed");
        }
        let updated = tx.execute(
            "UPDATE runtime_imports
                SET status='completed', result_snapshot_id=?2, completed_at=?3
              WHERE id=?1 AND status='staging' AND result_snapshot_id IS NULL",
            params![import_id, snapshot_id, completed_at],
        )?;
        if updated != 1 {
            bail!("runtime import staging transition was not applied");
        }
        tx.execute(
            "DELETE FROM runtime_import_operation_owners WHERE import_id=?1",
            [import_id],
        )?;
        promote_runtime_snapshot_if_parent_is_current(&tx, &parent_snapshot_id, &snapshot_id)?;
        tx.commit()?;
        Ok(RuntimeImportResult {
            import_id: import_id.to_owned(),
            session_id,
            snapshot_id,
            status: session.status,
            deduplicated: false,
        })
    }

    /// Discard a staged runtime import. No completed snapshot or current
    /// pointer has been created at this point.
    pub fn cancel_runtime_session_import_for_operation(
        &mut self,
        import_id: &str,
        operation_id: &str,
    ) -> Result<bool> {
        reject_reserved_runtime_import_operation_id(operation_id)?;
        let tx = self.connection.transaction()?;
        let session_id = tx
            .query_row(
                "SELECT session_id FROM runtime_imports
                  WHERE id=?1 AND status='staging' AND result_snapshot_id IS NULL",
                [import_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(session_id) = session_id else {
            tx.commit()?;
            return Ok(false);
        };
        let released = tx.execute(
            "DELETE FROM runtime_import_operation_owners
              WHERE import_id=?1 AND operation_id=?2",
            params![import_id, operation_id],
        )?;
        if released == 0 {
            // Absence fails safe: retain the stage for another durable owner or
            // recovery instead of guessing that this caller owns deletion.
            tx.commit()?;
            return Ok(false);
        }
        if released != 1 {
            bail!("runtime import owner release was not unique");
        }
        delete_unowned_staged_runtime_import(&tx, import_id, &session_id)?;
        tx.commit()?;
        Ok(true)
    }

    /// Idempotently remove only the staged evidence bound to a durable runtime
    /// operation. Completed imports and sessions referenced by another import
    /// are never deleted.
    pub fn cancel_matching_staged_runtime_session_import(
        &mut self,
        base_snapshot_id: &str,
        session_id: &str,
        trace_digest: &str,
        operation_id: &str,
    ) -> Result<bool> {
        reject_reserved_runtime_import_operation_id(operation_id)?;
        let tx = self.connection.transaction()?;
        let matching = tx
            .query_row(
                "SELECT import.id, session.trace_digest
                   FROM runtime_imports AS import
                   JOIN runtime_sessions AS session ON session.id=import.session_id
                  WHERE import.parent_snapshot_id=?1
                    AND import.session_id=?2
                    AND import.status='staging'
                    AND import.result_snapshot_id IS NULL",
                params![base_snapshot_id, session_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((import_id, stored_trace_digest)) = matching else {
            tx.commit()?;
            return Ok(false);
        };
        if stored_trace_digest != trace_digest {
            bail!("staged runtime import trace identity does not match");
        }
        let released = tx.execute(
            "DELETE FROM runtime_import_operation_owners
              WHERE import_id=?1 AND operation_id=?2",
            params![import_id, operation_id],
        )?;
        if released == 0 {
            tx.commit()?;
            return Ok(false);
        }
        if released != 1 {
            bail!("runtime import owner release was not unique");
        }
        delete_unowned_staged_runtime_import(&tx, &import_id, session_id)?;
        tx.commit()?;
        Ok(true)
    }

    /// Idempotently release staging selected solely through the unique durable
    /// operation owner. This is the cleanup path for legacy journal input that
    /// did not retain an external session or trace selector.
    pub fn cancel_staged_runtime_session_import_for_operation(
        &mut self,
        operation_id: &str,
    ) -> Result<bool> {
        reject_reserved_runtime_import_operation_id(operation_id)?;
        if !valid_runtime_import_operation_id(operation_id) {
            bail!("runtime import operation identity is invalid");
        }
        let tx = self.connection.transaction()?;
        let owned = tx
            .query_row(
                "SELECT owner.import_id, import.session_id, import.status,
                        import.result_snapshot_id
                   FROM runtime_import_operation_owners AS owner
                   JOIN runtime_imports AS import ON import.id=owner.import_id
                  WHERE owner.operation_id=?1",
                [operation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((import_id, session_id, status, result_snapshot_id)) = owned else {
            tx.commit()?;
            return Ok(false);
        };
        if status != "staging" || result_snapshot_id.is_some() {
            bail!("runtime import operation owner does not select mutable staging");
        }
        let released = tx.execute(
            "DELETE FROM runtime_import_operation_owners
              WHERE import_id=?1 AND operation_id=?2",
            params![import_id, operation_id],
        )?;
        if released != 1 {
            bail!("runtime import operation owner release was not unique");
        }
        delete_unowned_staged_runtime_import(&tx, &import_id, &session_id)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn runtime_session(&self, session_id: &str) -> Result<Option<RuntimeSessionRecord>> {
        load_runtime_session_record(&self.connection, session_id)
    }

    pub fn runtime_sessions_for_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Vec<RuntimeSessionRecord>> {
        let snapshot = self
            .completed_snapshot(snapshot_id)?
            .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
        snapshot
            .runtime_session_ids
            .iter()
            .map(|session_id| {
                load_runtime_session_record(&self.connection, session_id)?.with_context(|| {
                    format!("runtime session {session_id} referenced by snapshot was not found")
                })
            })
            .collect()
    }
}

fn promote_runtime_snapshot_if_parent_is_current(
    connection: &Connection,
    parent_snapshot_id: &str,
    snapshot_id: &str,
) -> Result<bool> {
    let current_snapshot_id = connection
        .query_row(
            "SELECT snapshot_id FROM current_completed_snapshot WHERE singleton=1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if current_snapshot_id.as_deref() != Some(parent_snapshot_id) {
        return Ok(false);
    }
    promote_completed_snapshot(connection, snapshot_id)?;
    Ok(true)
}

fn attach_runtime_import_operation_owner(
    connection: &mut Connection,
    import_id: &str,
    base_snapshot_id: &str,
    session_id: &str,
    operation_id: &str,
) -> Result<()> {
    if !valid_runtime_import_operation_id(operation_id) {
        bail!("runtime import operation identity is invalid");
    }
    let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let tx = connection.transaction()?;
    let state = tx
        .query_row(
            "SELECT parent_snapshot_id, session_id, status, result_snapshot_id
               FROM runtime_imports WHERE id=?1",
            [import_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_parent, stored_session, status, result_snapshot_id)) = state else {
        bail!("staged runtime import disappeared before owner attachment");
    };
    if stored_parent != base_snapshot_id
        || stored_session != session_id
        || status != "staging"
        || result_snapshot_id.is_some()
    {
        bail!("runtime import is not eligible for owner attachment");
    }
    tx.execute(
        "INSERT INTO runtime_import_operation_owners(import_id, operation_id, created_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(import_id, operation_id) DO NOTHING",
        params![import_id, operation_id, created_at],
    )?;
    let attached: u64 = tx.query_row(
        "SELECT COUNT(*) FROM runtime_import_operation_owners
          WHERE import_id=?1 AND operation_id=?2",
        params![import_id, operation_id],
        |row| row.get(0),
    )?;
    if attached != 1 {
        bail!("runtime import operation owner was not attached");
    }
    tx.commit()?;
    Ok(())
}

fn valid_runtime_import_operation_id(operation_id: &str) -> bool {
    !operation_id.is_empty()
        && operation_id.len() <= 512
        && !operation_id.starts_with(crate::LEGACY_RUNTIME_IMPORT_OWNER_PREFIX)
}

fn runtime_import_identity(
    parent_snapshot_id: &str,
    session_id: &str,
    runtime_session_ids: &[String],
) -> String {
    stable_id_from_value(
        "runtime-import",
        &json!({
            "parent_snapshot_id": parent_snapshot_id,
            "session_id": session_id,
            "runtime_session_ids": runtime_session_ids,
        }),
    )
}

fn runtime_recovery_trace_matches(
    session_id: &str,
    source_session_id: &str,
    stored_trace_digest: &str,
    retained_trace_digest: Option<&str>,
) -> bool {
    match retained_trace_digest {
        Some(retained_trace_digest) => stored_trace_digest == retained_trace_digest,
        None => {
            stable_id_from_value(
                "runtime-session",
                &json!({
                    "source_session_id": source_session_id,
                    "trace_digest": stored_trace_digest,
                }),
            ) == session_id
        }
    }
}

fn reject_reserved_runtime_import_operation_id(operation_id: &str) -> Result<()> {
    if operation_id.starts_with(crate::LEGACY_RUNTIME_IMPORT_OWNER_PREFIX) {
        bail!("runtime import operation identity uses a reserved prefix");
    }
    Ok(())
}

fn clear_runtime_import_operation_owners(
    connection: &mut Connection,
    import_id: &str,
) -> Result<()> {
    let tx = connection.transaction()?;
    tx.execute(
        "DELETE FROM runtime_import_operation_owners WHERE import_id=?1",
        [import_id],
    )?;
    tx.commit()?;
    Ok(())
}

fn delete_unowned_staged_runtime_import(
    tx: &Transaction<'_>,
    import_id: &str,
    session_id: &str,
) -> Result<()> {
    let remaining_owners: u64 = tx.query_row(
        "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
        [import_id],
        |row| row.get(0),
    )?;
    if remaining_owners != 0 {
        return Ok(());
    }
    let deleted = tx.execute(
        "DELETE FROM runtime_imports
          WHERE id=?1
            AND session_id=?2
            AND status='staging'
            AND result_snapshot_id IS NULL",
        params![import_id, session_id],
    )?;
    if deleted != 1 {
        bail!("unowned staged runtime import cleanup changed concurrently");
    }
    tx.execute(
        "DELETE FROM runtime_sessions
          WHERE id=?1
            AND NOT EXISTS (
                SELECT 1 FROM runtime_imports WHERE session_id=?1
            )",
        [session_id],
    )?;
    Ok(())
}

fn normalize_runtime_delta(delta: &mut RuntimeSessionDelta) {
    delta.nodes.sort_by(|left, right| left.id.cmp(&right.id));
    delta.sites.sort_by(|left, right| left.id.cmp(&right.id));
    delta.edges.sort_by(|left, right| left.id.cmp(&right.id));
    delta.evidence.sort_by(|left, right| {
        left.owner_type
            .cmp(&right.owner_type)
            .then(left.owner_id.cmp(&right.owner_id))
            .then(left.ordinal.cmp(&right.ordinal))
    });
    delta.diagnostics.sort_by(|left, right| {
        left.ordinal
            .cmp(&right.ordinal)
            .then(left.id.cmp(&right.id))
    });
    delta.session.coverage.completeness.sort();
    delta.session.coverage.completeness.dedup();
    delta.session.coverage.reasons.sort();
    delta.session.coverage.reasons.dedup();
}

fn validate_runtime_union(base: &GraphSnapshot, delta: &RuntimeSessionDelta) -> Result<()> {
    let session = &delta.session;
    if session.id.trim().is_empty()
        || session.source_session_id.trim().is_empty()
        || session.trace_digest.trim().is_empty()
        || !matches!(session.status.as_str(), "completed" | "partial")
        || session.event_count == 0
        || session.observation_count == 0
        || session.first_observed_at > session.last_observed_at
    {
        bail!("runtime session metadata is invalid");
    }
    if session.profile.id != session.profile_id
        || session
            .profile
            .properties
            .get("profile_phase")
            .and_then(Value::as_str)
            != Some("runtime")
    {
        bail!("runtime session profile contract is invalid");
    }
    if !matches!(session.profile_status.as_str(), "resolved" | "unresolved")
        || session
            .profile
            .properties
            .get("profile_status")
            .and_then(Value::as_str)
            != Some(session.profile_status.as_str())
        || session.profile.environment != session.environment
    {
        bail!("runtime session profile status or environment is invalid");
    }
    if session.profile_status == "resolved" {
        let parent_id = session
            .parent_profile_id
            .as_deref()
            .context("resolved runtime profile has no parent")?;
        let parent = base
            .profiles
            .iter()
            .find(|profile| profile.id == parent_id)
            .with_context(|| format!("runtime parent profile {parent_id} was not found"))?;
        let effective_input_id = canonical_effective_input_id(parent);
        if declared_parent_profile_id(&session.profile) != Some(parent_id)
            || declared_effective_input_id(&session.profile) != Some(effective_input_id.as_str())
            || session.profile.language != parent.language
            || session.profile_reason.is_some()
        {
            bail!("runtime profile effective parent contract is invalid");
        }
    } else if session.parent_profile_id.is_some()
        || declared_parent_profile_id(&session.profile).is_some()
        || session.profile_reason.as_deref().is_none_or(str::is_empty)
    {
        bail!("unresolved runtime profile must retain one bounded reason and no parent");
    }

    let base_nodes = base
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let mut node_ids = base_nodes.keys().copied().collect::<BTreeSet<_>>();
    let mut delta_node_ids = BTreeSet::new();
    for node in &delta.nodes {
        if !delta_node_ids.insert(node.id.as_str()) {
            bail!("runtime node {} is duplicated", node.id);
        }
        if let Some(existing) = base_nodes.get(node.id.as_str()) {
            if **existing != *node {
                bail!("runtime node {} would overwrite the base graph", node.id);
            }
        } else if node.properties.get("runtime_only").and_then(Value::as_bool) != Some(true) {
            bail!("new runtime node {} is not an explicit sentinel", node.id);
        }
        node_ids.insert(node.id.as_str());
    }

    let base_sites = base
        .sites
        .iter()
        .map(|site| (site.id.as_str(), site))
        .collect::<BTreeMap<_, _>>();
    let mut site_ids = BTreeSet::new();
    for site in &delta.sites {
        if let Some(existing) = base_sites.get(site.id.as_str())
            && **existing != *site
        {
            bail!("runtime site {} conflicts with the base graph", site.id);
        }
        if !site_ids.insert(site.id.as_str())
            || site.profile_id != session.profile_id
            || site.precision != "observed"
            || !node_ids.contains(site.source.as_str())
            || site
                .target_ids
                .iter()
                .any(|target| !node_ids.contains(target.as_str()))
        {
            bail!(
                "runtime site {} is not authorized by the base graph",
                site.id
            );
        }
    }

    let base_edges = base
        .edges
        .iter()
        .map(|edge| (edge.id.as_str(), edge))
        .collect::<BTreeMap<_, _>>();
    let mut edge_ids = BTreeSet::new();
    let environment_name = session
        .environment
        .get("name")
        .and_then(Value::as_str)
        .context("runtime session environment has no name")?;
    for edge in &delta.edges {
        if let Some(existing) = base_edges.get(edge.id.as_str())
            && **existing != *edge
        {
            bail!("runtime edge {} conflicts with the base graph", edge.id);
        }
        if !edge_ids.insert(edge.id.as_str())
            || edge.phase != "runtime"
            || edge.precision != "observed"
            || edge.profile_id != session.profile_id
            || edge.environment != environment_name
            || !node_ids.contains(edge.source.as_str())
            || !node_ids.contains(edge.target.as_str())
            || edge
                .site_id
                .as_deref()
                .is_none_or(|site_id| !site_ids.contains(site_id))
        {
            bail!(
                "runtime edge {} is not authorized by the base graph",
                edge.id
            );
        }
    }

    let owners = site_ids
        .iter()
        .map(|id| ("site", *id))
        .chain(edge_ids.iter().map(|id| ("edge", *id)))
        .collect::<BTreeSet<_>>();
    let mut evidence_keys = BTreeSet::new();
    for evidence in &delta.evidence {
        let properties = evidence
            .properties
            .as_object()
            .context("runtime evidence properties must be an object")?;
        let first_observed_at = properties
            .get("first_observed_at")
            .and_then(Value::as_str)
            .context("runtime evidence has no first observation time")?;
        let last_observed_at = properties
            .get("last_observed_at")
            .and_then(Value::as_str)
            .context("runtime evidence has no last observation time")?;
        if !owners.contains(&(evidence.owner_type.as_str(), evidence.owner_id.as_str()))
            || evidence.kind != "runtime"
            || properties.get("session_id").and_then(Value::as_str) != Some(session.id.as_str())
            || properties.get("source_session_id").and_then(Value::as_str)
                != Some(session.source_session_id.as_str())
            || properties.get("environment") != Some(&session.environment)
            || properties.get("count").and_then(Value::as_u64) == Some(0)
            || properties.get("count").and_then(Value::as_u64).is_none()
            || first_observed_at > last_observed_at
            || first_observed_at < session.first_observed_at.as_str()
            || last_observed_at > session.last_observed_at.as_str()
            || !evidence_keys.insert((
                evidence.owner_type.as_str(),
                evidence.owner_id.as_str(),
                evidence.ordinal,
            ))
        {
            bail!("runtime evidence is not owned by its session graph");
        }
    }
    let mut diagnostic_ids = BTreeSet::new();
    for (ordinal, diagnostic) in delta.diagnostics.iter().enumerate() {
        if diagnostic.ordinal != ordinal as i64
            || diagnostic.id.trim().is_empty()
            || !diagnostic_ids.insert(diagnostic.id.as_str())
            || diagnostic
                .properties
                .get("session_id")
                .and_then(Value::as_str)
                != Some(session.id.as_str())
        {
            bail!("runtime diagnostics are not canonical for their session");
        }
    }
    if owners.iter().any(|(owner_type, owner_id)| {
        !delta.evidence.iter().any(|evidence| {
            evidence.owner_type == *owner_type
                && evidence.owner_id == *owner_id
                && evidence.ordinal == 0
        })
    }) {
        bail!("runtime graph owner is missing primary evidence");
    }
    Ok(())
}

fn store_runtime_session(tx: &Transaction<'_>, delta: &RuntimeSessionDelta) -> Result<()> {
    if let Some(existing) = tx
        .query_row(
            "SELECT trace_digest FROM runtime_sessions WHERE id=?1",
            [&delta.session.id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        if existing != delta.session.trace_digest {
            bail!(
                "runtime session identity collision for {}",
                delta.session.id
            );
        }
        return Ok(());
    }
    let session = &delta.session;
    tx.execute(
        "INSERT INTO runtime_sessions(
            id, base_snapshot_id, source_session_id, schema_version, status, trace_digest,
            profile_id, parent_profile_id, profile_status, profile_reason, profile_json,
            environment_json, redaction_json, started_at, ended_at, first_observed_at,
            last_observed_at, event_count, observation_count, resolved_targets,
            external_targets, unresolved_targets, redacted_values, coverage_json, created_at
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25
         )",
        params![
            session.id,
            session.base_snapshot_id,
            session.source_session_id,
            session.schema_version,
            session.status,
            session.trace_digest,
            session.profile_id,
            session.parent_profile_id,
            session.profile_status,
            session.profile_reason,
            serde_json::to_string(&session.profile)?,
            serde_json::to_string(&session.environment)?,
            serde_json::to_string(&session.redaction)?,
            session.started_at,
            session.ended_at,
            session.first_observed_at,
            session.last_observed_at,
            session.event_count,
            session.observation_count,
            session.resolved_targets,
            session.external_targets,
            session.unresolved_targets,
            session.redacted_values,
            serde_json::to_string(&session.coverage)?,
            session.created_at,
        ],
    )?;
    insert_json_rows(tx, "runtime_nodes", &session.id, &delta.nodes, |node| {
        node.id.as_str()
    })?;
    insert_json_rows(tx, "runtime_sites", &session.id, &delta.sites, |site| {
        site.id.as_str()
    })?;
    insert_json_rows(tx, "runtime_edges", &session.id, &delta.edges, |edge| {
        edge.id.as_str()
    })?;
    for evidence in &delta.evidence {
        tx.execute(
            "INSERT INTO runtime_evidence(
                session_id, owner_type, owner_id, ordinal, raw_json
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session.id,
                evidence.owner_type,
                evidence.owner_id,
                evidence.ordinal,
                serde_json::to_string(evidence)?,
            ],
        )?;
    }
    for diagnostic in &delta.diagnostics {
        tx.execute(
            "INSERT INTO runtime_diagnostics(session_id, ordinal, id, raw_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                session.id,
                diagnostic.ordinal,
                diagnostic.id,
                serde_json::to_string(diagnostic)?,
            ],
        )?;
    }
    Ok(())
}

fn insert_json_rows<T: Serialize>(
    tx: &Transaction<'_>,
    table: &str,
    session_id: &str,
    values: &[T],
    id: impl Fn(&T) -> &str,
) -> Result<()> {
    let sql = format!("INSERT INTO {table}(session_id, id, raw_json) VALUES (?1, ?2, ?3)");
    for value in values {
        tx.execute(
            &sql,
            params![session_id, id(value), serde_json::to_string(value)?],
        )?;
    }
    Ok(())
}

fn load_runtime_session_record(
    connection: &Connection,
    session_id: &str,
) -> Result<Option<RuntimeSessionRecord>> {
    connection
        .query_row(
            "SELECT id, base_snapshot_id, source_session_id, schema_version, status,
                    trace_digest, profile_id, parent_profile_id, profile_status,
                    profile_reason, profile_json, environment_json, redaction_json,
                    started_at, ended_at, first_observed_at, last_observed_at,
                    event_count, observation_count, resolved_targets, external_targets,
                    unresolved_targets, redacted_values, coverage_json, created_at
               FROM runtime_sessions WHERE id=?1",
            [session_id],
            |row| {
                let profile = decode_json_column(row, 10)?;
                let environment = decode_json_column(row, 11)?;
                let redaction = decode_json_column(row, 12)?;
                let coverage = decode_json_column(row, 23)?;
                Ok(RuntimeSessionRecord {
                    id: row.get(0)?,
                    base_snapshot_id: row.get(1)?,
                    source_session_id: row.get(2)?,
                    schema_version: row.get(3)?,
                    status: row.get(4)?,
                    trace_digest: row.get(5)?,
                    profile_id: row.get(6)?,
                    parent_profile_id: row.get(7)?,
                    profile_status: row.get(8)?,
                    profile_reason: row.get(9)?,
                    profile,
                    environment,
                    redaction,
                    started_at: row.get(13)?,
                    ended_at: row.get(14)?,
                    first_observed_at: row.get(15)?,
                    last_observed_at: row.get(16)?,
                    event_count: row.get(17)?,
                    observation_count: row.get(18)?,
                    resolved_targets: row.get(19)?,
                    external_targets: row.get(20)?,
                    unresolved_targets: row.get(21)?,
                    redacted_values: row.get(22)?,
                    coverage,
                    created_at: row.get(24)?,
                })
            },
        )
        .optional()
        .context("failed to load runtime session")
}

fn decode_json_column<T: for<'de> Deserialize<'de>>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<T> {
    let raw = row.get::<_, String>(index)?;
    serde_json::from_str(&raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            raw.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn load_runtime_delta(connection: &Connection, session_id: &str) -> Result<RuntimeSessionDelta> {
    let session = load_runtime_session_record(connection, session_id)?
        .with_context(|| format!("runtime session {session_id} was not found"))?;
    let nodes = load_json_rows(connection, "runtime_nodes", session_id)?;
    let sites = load_json_rows(connection, "runtime_sites", session_id)?;
    let edges = load_json_rows(connection, "runtime_edges", session_id)?;
    let evidence = load_json_rows_ordered(
        connection,
        "runtime_evidence",
        session_id,
        "owner_type, owner_id, ordinal",
    )?;
    let diagnostics =
        load_json_rows_ordered(connection, "runtime_diagnostics", session_id, "ordinal, id")?;
    Ok(RuntimeSessionDelta {
        session,
        nodes,
        sites,
        edges,
        evidence,
        diagnostics,
    })
}

fn load_json_rows<T: for<'de> Deserialize<'de>>(
    connection: &Connection,
    table: &str,
    session_id: &str,
) -> Result<Vec<T>> {
    load_json_rows_ordered(connection, table, session_id, "id")
}

fn load_json_rows_ordered<T: for<'de> Deserialize<'de>>(
    connection: &Connection,
    table: &str,
    session_id: &str,
    order: &str,
) -> Result<Vec<T>> {
    let sql = format!("SELECT raw_json FROM {table} WHERE session_id=?1 ORDER BY {order}");
    let mut statement = connection.prepare(&sql)?;
    statement
        .query_map([session_id], |row| {
            let raw = row.get::<_, String>(0)?;
            serde_json::from_str(&raw).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    raw.len(),
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub(super) fn merge_runtime_sessions(
    connection: &Connection,
    snapshot: &mut GraphSnapshot,
    runtime_session_ids: &[String],
) -> Result<()> {
    let canonical = runtime_session_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if canonical != runtime_session_ids {
        bail!("completed snapshot runtime session set is not canonical");
    }
    let mut profiles = snapshot
        .profiles
        .drain(..)
        .map(|profile| (profile.id.clone(), profile))
        .collect::<BTreeMap<_, _>>();
    let mut nodes = snapshot
        .nodes
        .drain(..)
        .map(|node| (node.id.clone(), node))
        .collect::<BTreeMap<_, _>>();
    let mut sites = snapshot
        .sites
        .drain(..)
        .map(|site| (site.id.clone(), site))
        .collect::<BTreeMap<_, _>>();
    let mut edges = snapshot
        .edges
        .drain(..)
        .map(|edge| (edge.id.clone(), edge))
        .collect::<BTreeMap<_, _>>();
    let mut evidence = snapshot.evidence.drain(..).collect::<Vec<_>>();
    let mut diagnostics = snapshot.diagnostics.drain(..).collect::<Vec<_>>();
    let mut diagnostic_indexes = diagnostics
        .iter()
        .enumerate()
        .map(|(index, diagnostic)| (diagnostic.id.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let mut next_diagnostic_ordinal = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.ordinal)
        .max()
        .unwrap_or(-1)
        .saturating_add(1);

    for session_id in runtime_session_ids {
        let delta = load_runtime_delta(connection, session_id)?;
        insert_exact(
            &mut profiles,
            delta.session.profile.id.clone(),
            delta.session.profile,
        )?;
        for node in delta.nodes {
            insert_exact(&mut nodes, node.id.clone(), node)?;
        }
        for site in delta.sites {
            insert_exact(&mut sites, site.id.clone(), site)?;
        }
        for edge in delta.edges {
            insert_exact(&mut edges, edge.id.clone(), edge)?;
        }
        evidence.extend(delta.evidence);
        for mut diagnostic in delta.diagnostics {
            if let Some(index) = diagnostic_indexes.get(&diagnostic.id) {
                if diagnostics[*index] != diagnostic {
                    bail!("runtime graph identity collision for {}", diagnostic.id);
                }
                continue;
            }
            diagnostic.ordinal = next_diagnostic_ordinal;
            next_diagnostic_ordinal = next_diagnostic_ordinal.saturating_add(1);
            diagnostic_indexes.insert(diagnostic.id.clone(), diagnostics.len());
            diagnostics.push(diagnostic);
        }
        union_runtime_coverage_metadata(&mut snapshot.coverage, &delta.session.coverage);
    }
    reassign_runtime_evidence_ordinals(&mut evidence);
    snapshot.profiles = profiles.into_values().collect();
    snapshot.nodes = nodes.into_values().collect();
    snapshot.sites = sites.into_values().collect();
    snapshot.edges = edges.into_values().collect();
    snapshot.evidence = evidence;
    snapshot.diagnostics = diagnostics;
    snapshot.coverage.profiles = snapshot.profiles.len() as u64;
    snapshot.coverage.dependency_sites = snapshot.sites.len() as u64;
    snapshot.coverage.resolved = 0;
    snapshot.coverage.candidates = 0;
    snapshot.coverage.external = 0;
    snapshot.coverage.unresolved = 0;
    for site in &snapshot.sites {
        match site.resolution_status.as_str() {
            "resolved" => snapshot.coverage.resolved += 1,
            "candidates" => snapshot.coverage.candidates += 1,
            "external" => snapshot.coverage.external += 1,
            "unresolved" => snapshot.coverage.unresolved += 1,
            _ => {}
        }
    }
    refresh_profile_matrix(snapshot, false);
    Ok(())
}

pub(super) fn union_runtime_coverage_metadata(
    target: &mut CoverageRecord,
    session: &CoverageRecord,
) {
    target.unsupported_syntax = target
        .unsupported_syntax
        .saturating_add(session.unsupported_syntax);
    target.project_code_executed |= session.project_code_executed;
    target
        .completeness
        .extend(session.completeness.iter().cloned());
    target.completeness.sort();
    target.completeness.dedup();
    target.reasons.extend(session.reasons.iter().cloned());
    target.reasons.sort();
    target.reasons.dedup();
}

fn insert_exact<T: PartialEq>(
    values: &mut BTreeMap<String, T>,
    id: String,
    value: T,
) -> Result<()> {
    if let Some(existing) = values.get(&id) {
        if *existing != value {
            bail!("runtime graph identity collision for {id}");
        }
    } else {
        values.insert(id, value);
    }
    Ok(())
}

fn reassign_runtime_evidence_ordinals(evidence: &mut [EvidenceRecord]) {
    evidence.sort_by(|left, right| {
        left.owner_type
            .cmp(&right.owner_type)
            .then(left.owner_id.cmp(&right.owner_id))
            .then_with(|| {
                evidence_session_id(left)
                    .cmp(evidence_session_id(right))
                    .then(left.ordinal.cmp(&right.ordinal))
            })
    });
    let mut previous = None::<(String, String)>;
    let mut ordinal = 0_i64;
    for item in evidence {
        let owner = (item.owner_type.clone(), item.owner_id.clone());
        if previous.as_ref() != Some(&owner) {
            previous = Some(owner);
            ordinal = 0;
        }
        item.ordinal = ordinal;
        ordinal += 1;
    }
}

fn evidence_session_id(evidence: &EvidenceRecord) -> &str {
    evidence
        .properties
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("")
}

pub fn runtime_context_for_edge(snapshot: &GraphSnapshot, edge: &EdgeRecord) -> RuntimeEdgeContext {
    let mut context = RuntimeEdgeContext::default();
    for evidence in snapshot.evidence.iter().filter(|evidence| {
        evidence.owner_type == "edge" && evidence.owner_id == edge.id && evidence.kind == "runtime"
    }) {
        push_string(
            &mut context.session_ids,
            evidence.properties.get("session_id"),
        );
        push_string(
            &mut context.source_session_ids,
            evidence.properties.get("source_session_id"),
        );
        if let Some(environment) = evidence.properties.get("environment") {
            push_string(&mut context.environment_names, environment.get("name"));
            push_string(&mut context.runtimes, environment.get("runtime"));
            push_string(&mut context.regions, environment.get("region"));
        }
        context.observation_count = context.observation_count.saturating_add(
            evidence
                .properties
                .get("count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        update_min(
            &mut context.first_observed_at,
            evidence
                .properties
                .get("first_observed_at")
                .and_then(Value::as_str),
        );
        update_max(
            &mut context.last_observed_at,
            evidence
                .properties
                .get("last_observed_at")
                .and_then(Value::as_str),
        );
    }
    context.session_ids.sort();
    context.session_ids.dedup();
    context.source_session_ids.sort();
    context.source_session_ids.dedup();
    context.environment_names.sort();
    context.environment_names.dedup();
    context.runtimes.sort();
    context.runtimes.dedup();
    context.regions.sort();
    context.regions.dedup();
    context
}

fn push_string(output: &mut Vec<String>, value: Option<&Value>) {
    if let Some(value) = value.and_then(Value::as_str) {
        output.push(value.to_owned());
    }
}

fn update_min(current: &mut Option<String>, value: Option<&str>) {
    if let Some(value) = value
        && current.as_deref().is_none_or(|current| value < current)
    {
        *current = Some(value.to_owned());
    }
}

fn update_max(current: &mut Option<String>, value: Option<&str>) {
    if let Some(value) = value
        && current.as_deref().is_none_or(|current| value > current)
    {
        *current = Some(value.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn seeded_store() -> Result<(Store, String, GraphSnapshot)> {
        let mut store = Store::open_in_memory()?;
        store.start_scan_with_revision(
            "runtime-atomic",
            Path::new("/fixture"),
            false,
            Some("revision-1"),
        )?;
        let coverage = json!({
            "profiles":1,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
            "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        let common = |event: &str, seq: u64| {
            json!({
                "event":event,"protocol_version":"1.0","scan_id":"runtime-atomic",
                "adapter":"fixture","adapter_version":"1.0","seq":seq
            })
        };
        let mut started = common("scan_started", 1);
        started["root"] = json!("/fixture");
        started["project_code_executed"] = json!(false);
        started["safe_mode"] = json!(true);
        store.ingest_event(&started)?;
        let mut profile = common("profile_declared", 2);
        profile["profile"] = json!({
            "id":"profile:base","language":"typescript","target":"server",
            "features":[],"environment":{},"source_revision":"revision-1","properties":{}
        });
        store.ingest_event(&profile)?;
        for (offset, node) in [
            json!({
                "id":"workspace:fixture","kind":"workspace",
                "locator":"workspace://repository:fixture","display_name":"fixture",
                "properties":{"repository_identity":"repository:fixture"}
            }),
            json!({
                "id":"file:source","kind":"file","locator":"file://src/source.ts",
                "display_name":"source.ts","properties":{"path":"src/source.ts"}
            }),
            json!({
                "id":"route:target","kind":"route","locator":"route:/target",
                "display_name":"/target","properties":{}
            }),
        ]
        .into_iter()
        .enumerate()
        {
            let mut event = common("node_upsert", offset as u64 + 3);
            event["node"] = node;
            store.ingest_event(&event)?;
        }
        let mut profile_completed = common("profile_completed", 6);
        profile_completed["profile_id"] = json!("profile:base");
        profile_completed["coverage"] = coverage.clone();
        store.ingest_event(&profile_completed)?;
        let mut completed = common("scan_completed", 7);
        completed["coverage"] = coverage;
        store.ingest_event(&completed)?;
        store.finish_scan("runtime-atomic", "completed", None, true)?;
        let snapshot_id = store.current_snapshot_id()?.context("base snapshot")?;
        let snapshot = store.load_completed_snapshot(&snapshot_id)?;
        Ok((store, snapshot_id, snapshot))
    }

    fn assert_node_page_matches_snapshot(
        store: &mut Store,
        snapshot_id: &str,
        snapshot: &GraphSnapshot,
    ) -> Result<()> {
        let expected = snapshot
            .nodes
            .iter()
            .map(|node| super::super::NodeSummaryRecord {
                id: node.id.clone(),
                kind: node.kind.clone(),
                locator: node.locator.clone(),
                display_name: node.display_name.clone(),
            })
            .collect::<Vec<_>>();
        let page = store.find_completed_snapshot_nodes_page(
            snapshot_id,
            "",
            super::super::NodeTextMatch::Contains,
            &[],
            0,
            expected.len().max(1),
            || false,
        )?;
        assert_eq!(page.total_items, expected.len() as u64);
        assert_eq!(page.items, expected);
        Ok(())
    }

    #[test]
    fn paged_node_projection_rejects_invalid_runtime_metadata_and_non_node_rows() -> Result<()> {
        for corruption in ["metadata", "edge"] {
            let (mut store, base_snapshot_id, base) = seeded_store()?;
            let imported = store
                .import_runtime_session(&base_snapshot_id, valid_delta(&base_snapshot_id, &base))?;
            match corruption {
                "metadata" => {
                    store.connection.execute(
                        "UPDATE runtime_sessions
                            SET coverage_json=json_set(coverage_json, '$.profiles', 'invalid')
                          WHERE id=?1",
                        [&imported.session_id],
                    )?;
                }
                "edge" => {
                    store.connection.execute(
                        "UPDATE runtime_edges
                            SET raw_json=json_set(raw_json, '$.generated', 'invalid')
                          WHERE session_id=?1",
                        [&imported.session_id],
                    )?;
                }
                _ => unreachable!(),
            }

            store
                .load_completed_snapshot(&imported.snapshot_id)
                .expect_err("canonical runtime decoding must reject the corruption");
            store
                .find_completed_snapshot_nodes_page(
                    &imported.snapshot_id,
                    "",
                    super::super::NodeTextMatch::Contains,
                    &[],
                    0,
                    10,
                    || false,
                )
                .expect_err("paged projection must reject the same runtime corruption");
        }
        Ok(())
    }

    fn valid_delta(base_snapshot_id: &str, base: &GraphSnapshot) -> RuntimeSessionDelta {
        let profile_id = "profile:runtime".to_owned();
        let session_id = "runtime-session:test".to_owned();
        let coverage = CoverageRecord {
            profiles: 1,
            dependency_sites: 1,
            resolved: 1,
            project_code_executed: true,
            completeness: vec!["runtime-observed".to_owned()],
            ..CoverageRecord::default()
        };
        let profile = ProfileRecord {
            id: profile_id.clone(),
            language: "typescript".to_owned(),
            toolchain: None,
            command: None,
            target: Some("server".to_owned()),
            features: Vec::new(),
            environment: json!({"name":"test"}),
            source_revision: Some("revision-1".to_owned()),
            properties: json!({
                "profile_phase":"runtime",
                "parent_profile_id":"profile:base",
                "effective_input_id":canonical_effective_input_id(&base.profiles[0]),
                "profile_status":"resolved",
                "profile_reason":null,
            }),
            coverage: None,
        };
        let properties = json!({
            "session_id":session_id,
            "source_session_id":"collector-session",
            "environment":{"name":"test"},
            "count":1,
            "first_observed_at":"2026-07-23T00:00:01Z",
            "last_observed_at":"2026-07-23T00:00:01Z"
        });
        RuntimeSessionDelta {
            session: RuntimeSessionRecord {
                id: session_id,
                base_snapshot_id: base_snapshot_id.to_owned(),
                source_session_id: "collector-session".to_owned(),
                schema_version: "1.0".to_owned(),
                status: "completed".to_owned(),
                trace_digest: "runtime-trace:sha256:test".to_owned(),
                profile_id: profile_id.clone(),
                parent_profile_id: Some("profile:base".to_owned()),
                profile_status: "resolved".to_owned(),
                profile_reason: None,
                profile,
                environment: json!({"name":"test"}),
                redaction: json!({"redacted_value_count":0}),
                started_at: "2026-07-23T00:00:00Z".to_owned(),
                ended_at: Some("2026-07-23T00:00:02Z".to_owned()),
                first_observed_at: "2026-07-23T00:00:01Z".to_owned(),
                last_observed_at: "2026-07-23T00:00:01Z".to_owned(),
                event_count: 1,
                observation_count: 1,
                resolved_targets: 1,
                external_targets: 0,
                unresolved_targets: 0,
                redacted_values: 0,
                coverage,
                created_at: "2026-07-23T00:00:03Z".to_owned(),
            },
            nodes: Vec::new(),
            sites: vec![SiteRecord {
                id: "site:runtime".to_owned(),
                source: "file:source".to_owned(),
                kind: "calls".to_owned(),
                specifier: Some("route:/target".to_owned()),
                profile_id: profile_id.clone(),
                resolution_status: "resolved".to_owned(),
                precision: "observed".to_owned(),
                condition: json!({"op":"true"}),
                target_ids: vec!["route:target".to_owned()],
                reason: None,
            }],
            edges: vec![EdgeRecord {
                id: "edge:runtime".to_owned(),
                site_id: Some("site:runtime".to_owned()),
                source: "file:source".to_owned(),
                target: "route:target".to_owned(),
                kind: "calls".to_owned(),
                phase: "runtime".to_owned(),
                environment: "test".to_owned(),
                profile_id,
                resolution_status: "resolved".to_owned(),
                precision: "observed".to_owned(),
                condition: json!({"op":"true"}),
                generated: false,
            }],
            evidence: vec![
                runtime_test_evidence("site", "site:runtime", properties.clone()),
                runtime_test_evidence("edge", "edge:runtime", properties),
            ],
            diagnostics: Vec::new(),
        }
    }

    fn runtime_test_evidence(
        owner_type: &str,
        owner_id: &str,
        properties: Value,
    ) -> EvidenceRecord {
        EvidenceRecord {
            owner_type: owner_type.to_owned(),
            owner_id: owner_id.to_owned(),
            ordinal: 0,
            kind: "runtime".to_owned(),
            extractor: "runtime-trace".to_owned(),
            extractor_version: "1.0".to_owned(),
            path: String::new(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
            detail: None,
            properties,
        }
    }

    #[test]
    fn runtime_context_aggregates_sessions_and_time_range() {
        let edge = EdgeRecord {
            id: "edge:runtime".to_owned(),
            site_id: Some("site:runtime".to_owned()),
            source: "node:a".to_owned(),
            target: "node:b".to_owned(),
            kind: "calls".to_owned(),
            phase: "runtime".to_owned(),
            environment: "production".to_owned(),
            profile_id: "profile:runtime".to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "observed".to_owned(),
            condition: json!({"op":"true"}),
            generated: false,
        };
        let evidence = |session: &str, count: u64, first: &str, last: &str| EvidenceRecord {
            owner_type: "edge".to_owned(),
            owner_id: edge.id.clone(),
            ordinal: 0,
            kind: "runtime".to_owned(),
            extractor: "runtime-trace".to_owned(),
            extractor_version: "1.0".to_owned(),
            path: String::new(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
            detail: None,
            properties: json!({
                "session_id":session,
                "source_session_id":session,
                "environment":{"name":"production","runtime":"node"},
                "count":count,
                "first_observed_at":first,
                "last_observed_at":last,
            }),
        };
        let snapshot = GraphSnapshot {
            scan: super::super::ScanRecord {
                id: "scan".to_owned(),
                root: ".".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: String::new(),
                completed_at: None,
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: None,
            },
            profiles: Vec::new(),
            nodes: Vec::new(),
            sites: Vec::new(),
            edges: vec![edge.clone()],
            evidence: vec![
                evidence(
                    "session:b",
                    3,
                    "2026-01-02T00:00:00Z",
                    "2026-01-03T00:00:00Z",
                ),
                evidence(
                    "session:a",
                    2,
                    "2026-01-01T00:00:00Z",
                    "2026-01-04T00:00:00Z",
                ),
            ],
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: super::super::ProfileMatrixRecord::default(),
        };
        let context = runtime_context_for_edge(&snapshot, &edge);
        assert_eq!(context.session_ids, ["session:a", "session:b"]);
        assert_eq!(context.observation_count, 5);
        assert_eq!(
            context.first_observed_at.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            context.last_observed_at.as_deref(),
            Some("2026-01-04T00:00:00Z")
        );
    }

    #[test]
    fn failed_promotion_rolls_back_every_runtime_row_and_pointer_change() -> Result<()> {
        let (mut store, base_snapshot_id, base) = seeded_store()?;
        let delta = valid_delta(&base_snapshot_id, &base);
        store.connection.execute_batch(
            "CREATE TRIGGER reject_runtime_promotion
             BEFORE UPDATE ON current_completed_snapshot
             BEGIN SELECT RAISE(ABORT, 'injected runtime promotion failure'); END;",
        )?;
        let error = store
            .import_runtime_session(&base_snapshot_id, delta)
            .unwrap_err()
            .to_string();
        assert!(error.contains("injected runtime promotion failure"));
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(base_snapshot_id.as_str())
        );
        assert!(store.runtime_session("runtime-session:test")?.is_none());
        let runtime_imports: u64 =
            store
                .connection
                .query_row("SELECT COUNT(*) FROM runtime_imports", [], |row| row.get(0))?;
        assert_eq!(runtime_imports, 0);
        let runtime_snapshots: u64 = store.connection.query_row(
            "SELECT COUNT(*) FROM completed_snapshots WHERE source_kind='runtime'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(runtime_snapshots, 0);
        Ok(())
    }

    #[test]
    fn deferred_recovery_completes_import_without_replacing_newer_current_snapshot() -> Result<()> {
        let (mut store, base_snapshot_id, base) = seeded_store()?;
        let staged = store
            .prepare_runtime_session_import(
                &base_snapshot_id,
                valid_delta(&base_snapshot_id, &base),
                "op_store_deferred_recovery",
            )?
            .into_result();

        let mut newer_delta = valid_delta(&base_snapshot_id, &base);
        newer_delta.session.id = "runtime-session:newer".to_owned();
        newer_delta.session.source_session_id = "collector-session-newer".to_owned();
        newer_delta.session.trace_digest = "runtime-trace:sha256:newer".to_owned();
        for evidence in &mut newer_delta.evidence {
            evidence.properties["session_id"] = json!(newer_delta.session.id);
            evidence.properties["source_session_id"] = json!(newer_delta.session.source_session_id);
        }
        let newer = store.import_runtime_session(&base_snapshot_id, newer_delta)?;
        assert_ne!(newer.snapshot_id, staged.snapshot_id);
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(newer.snapshot_id.as_str())
        );

        let recovered = store.promote_runtime_session_import(
            &staged.import_id,
            &staged.session_id,
            &staged.snapshot_id,
        )?;

        assert_eq!(recovered.snapshot_id, staged.snapshot_id);
        let completed = store
            .completed_snapshot(&staged.snapshot_id)?
            .context("recovered runtime snapshot")?;
        assert_eq!(completed.status, "completed");
        assert_eq!(
            completed.runtime_import_id.as_deref(),
            Some(staged.import_id.as_str())
        );
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(newer.snapshot_id.as_str())
        );
        Ok(())
    }

    #[test]
    fn operation_only_runtime_cleanup_is_idempotent_and_rejects_reserved_owners() -> Result<()> {
        let (mut store, base_snapshot_id, base) = seeded_store()?;
        let operation_id = "op_00000000000000000000000000000003";
        let staged = store
            .prepare_runtime_session_import(
                &base_snapshot_id,
                valid_delta(&base_snapshot_id, &base),
                operation_id,
            )?
            .into_result();

        assert!(store.cancel_staged_runtime_session_import_for_operation(operation_id)?);
        assert!(!store.cancel_staged_runtime_session_import_for_operation(operation_id)?);
        assert!(store.runtime_session(&staged.session_id)?.is_none());
        assert_eq!(
            store.connection.query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1",
                [&staged.import_id],
                |row| row.get::<_, u64>(0),
            )?,
            0
        );

        let sentinel = crate::legacy_runtime_import_owner_id(&staged.import_id);
        assert!(
            store
                .cancel_staged_runtime_session_import_for_operation(&sentinel)
                .unwrap_err()
                .to_string()
                .contains("reserved prefix")
        );
        Ok(())
    }

    #[test]
    fn v15_staging_migrates_with_a_reserved_owner_until_recovery_promotion() -> Result<()> {
        let (mut store, base_snapshot_id, base) = seeded_store()?;
        let staged = store
            .prepare_runtime_session_import(
                &base_snapshot_id,
                valid_delta(&base_snapshot_id, &base),
                "op_pre_v16_owner_not_persisted",
            )?
            .into_result();
        store.connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             DROP TABLE runtime_import_operation_owners;
             PRAGMA user_version=15;",
        )?;

        store.migrate()?;
        assert_eq!(store.schema_version()?, crate::STORE_SCHEMA_VERSION);
        let sentinel = crate::legacy_runtime_import_owner_id(&staged.import_id);
        assert_eq!(
            store.connection.query_row(
                "SELECT operation_id FROM runtime_import_operation_owners
                  WHERE import_id=?1",
                [&staged.import_id],
                |row| row.get::<_, String>(0),
            )?,
            sentinel
        );
        assert!(!store.cancel_runtime_session_import_for_operation(
            &staged.import_id,
            "op_pre_v16_owner_not_persisted"
        )?);

        let attached = store
            .prepare_runtime_session_import(
                &base_snapshot_id,
                valid_delta(&base_snapshot_id, &base),
                "op_post_v16_owner",
            )?
            .into_result();
        assert_eq!(attached.import_id, staged.import_id);
        assert!(
            store.cancel_runtime_session_import_for_operation(
                &staged.import_id,
                "op_post_v16_owner"
            )?
        );
        assert_eq!(
            store.connection.query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                [&staged.import_id],
                |row| row.get::<_, u64>(0),
            )?,
            1
        );
        let session = store
            .runtime_session(&staged.session_id)?
            .context("legacy staged runtime session")?;
        assert_eq!(
            store.connection.query_row(
                "SELECT operation_id FROM runtime_import_operation_owners
                  WHERE import_id=?1",
                [&staged.import_id],
                |row| row.get::<_, String>(0),
            )?,
            sentinel
        );
        assert!(
            store
                .cancel_runtime_session_import_for_operation(&staged.import_id, &sentinel)
                .unwrap_err()
                .to_string()
                .contains("reserved prefix")
        );
        assert!(
            store
                .cancel_matching_staged_runtime_session_import(
                    &base_snapshot_id,
                    &staged.session_id,
                    &session.trace_digest,
                    &sentinel,
                )
                .unwrap_err()
                .to_string()
                .contains("reserved prefix")
        );
        assert!(
            store
                .cancel_staged_runtime_session_import_for_operation(&sentinel)
                .unwrap_err()
                .to_string()
                .contains("reserved prefix")
        );

        assert!(
            store
                .recover_runtime_session_import_for_operation(&RuntimeImportRecoveryIdentity::new(
                    &staged.import_id,
                    &staged.session_id,
                    &staged.snapshot_id,
                    &base_snapshot_id,
                    &session.trace_digest,
                    &session.status,
                    &sentinel,
                ))
                .unwrap_err()
                .to_string()
                .contains("reserved prefix")
        );
        let promoted = store.recover_runtime_session_import_for_operation(
            &RuntimeImportRecoveryIdentity::new(
                &staged.import_id,
                &staged.session_id,
                &staged.snapshot_id,
                &base_snapshot_id,
                &session.trace_digest,
                &session.status,
                "op_pre_v16_recovery_intent",
            ),
        )?;
        assert_eq!(promoted.snapshot_id, staged.snapshot_id);
        assert_eq!(
            store.connection.query_row(
                "SELECT COUNT(*) FROM runtime_import_operation_owners",
                [],
                |row| row.get::<_, u64>(0),
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn later_build_promotion_preserves_imported_runtime_sessions() -> Result<()> {
        let (mut store, base_snapshot_id, base) = seeded_store()?;
        let mut delta = valid_delta(&base_snapshot_id, &base);
        delta.nodes.push(NodeRecord {
            id: "runtime:build-layer".to_owned(),
            kind: "runtime_target".to_owned(),
            locator: "runtime://build-layer".to_owned(),
            display_name: "runtime build layer".to_owned(),
            properties: json!({"runtime_only": true}),
        });
        delta.diagnostics.push(DiagnosticRecord {
            ordinal: 0,
            id: "diagnostic:runtime".to_owned(),
            severity: "warning".to_owned(),
            code: "runtime-observed".to_owned(),
            message: "runtime observation retained".to_owned(),
            path: None,
            adapter: Some("runtime-trace".to_owned()),
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            properties: json!({
                "session_id":"runtime-session:test",
                "private_payload":"must-not-appear-in-doctor-summary"
            }),
        });
        let imported = store.import_runtime_session(&base_snapshot_id, delta)?;
        let imported_snapshot = store.load_completed_snapshot(&imported.snapshot_id)?;
        assert_node_page_matches_snapshot(&mut store, &imported.snapshot_id, &imported_snapshot)?;
        let audit = json!({
            "schema_version":"1.0",
            "run_id":"build-after-runtime",
            "adapter":"build-observer",
            "adapter_version":"0.1.0",
            "profile_id":"profile:build",
            "command_plan_digest":"a".repeat(64),
            "toolchain_executable_digest":"b".repeat(64),
            "environment_key_set_digest":"c".repeat(64),
            "validated_output_digest":"d".repeat(64),
            "outcome":"completed",
            "started_at":"2026-07-23T00:00:04.000Z",
            "finished_at":"2026-07-23T00:00:05.000Z",
            "environment_keys":["CI","PATH"]
        });
        store.save_build_audit(&audit)?;
        store.start_build_attempt("runtime-atomic", &audit)?;
        store.connection.execute(
            "UPDATE build_attempts SET delta_json=?2 WHERE id=?1",
            params![
                "build-after-runtime",
                serde_json::to_string(&super::super::BuildGraphDelta::default())?
            ],
        )?;

        store.finish_build_attempt("build-after-runtime", "completed", None, true)?;

        let current_id = store.current_snapshot_id()?.context("build snapshot")?;
        let metadata = store
            .completed_snapshot(&current_id)?
            .context("build snapshot metadata")?;
        assert_eq!(metadata.source_kind, "build");
        assert_eq!(
            metadata.build_attempt_id.as_deref(),
            Some("build-after-runtime")
        );
        assert_eq!(metadata.runtime_session_ids, [imported.session_id]);
        assert_eq!(
            metadata.parent_snapshot_id.as_deref(),
            Some(imported.snapshot_id.as_str())
        );
        let snapshot = store.load_completed_snapshot(&current_id)?;
        assert!(snapshot.edges.iter().any(|edge| edge.id == "edge:runtime"));
        assert!(
            snapshot
                .nodes
                .iter()
                .any(|node| node.id == "runtime:build-layer")
        );
        assert_node_page_matches_snapshot(&mut store, &current_id, &snapshot)?;
        let doctor_summary = store.scan_attempt_summary("runtime-atomic")?;
        assert_eq!(doctor_summary.coverage, snapshot.coverage);
        assert_eq!(
            doctor_summary.profile_count,
            u64::try_from(snapshot.profiles.len())?
        );
        let mut expected_profiles_by_language = BTreeMap::new();
        for profile in &snapshot.profiles {
            *expected_profiles_by_language
                .entry(profile.language.clone())
                .or_default() += 1;
        }
        assert_eq!(
            doctor_summary.profiles_by_language,
            expected_profiles_by_language
        );
        assert_eq!(
            doctor_summary.diagnostics.total,
            u64::try_from(
                snapshot
                    .diagnostics
                    .iter()
                    .filter(|diagnostic| {
                        diagnostic.properties.get("profile_matrix_schema").is_none()
                    })
                    .count()
            )?
        );
        assert!(
            doctor_summary
                .diagnostics
                .groups
                .iter()
                .any(|group| group.code == "runtime-observed" && group.count == 1)
        );
        assert!(
            !serde_json::to_string(&doctor_summary)?.contains("must-not-appear-in-doctor-summary")
        );
        assert!(store.verify_snapshot_integrity(&current_id)?.valid);
        Ok(())
    }

    #[test]
    fn multiple_sessions_keep_coverage_aligned_with_the_deduplicated_graph() -> Result<()> {
        let (mut store, base_snapshot_id, base) = seeded_store()?;
        let first = store
            .import_runtime_session(&base_snapshot_id, valid_delta(&base_snapshot_id, &base))?;
        let mut second = valid_delta(&first.snapshot_id, &base);
        second.session.id = "runtime-session:test-2".to_owned();
        second.session.source_session_id = "collector-session-2".to_owned();
        second.session.trace_digest = "runtime-trace:sha256:test-2".to_owned();
        for evidence in &mut second.evidence {
            evidence.properties["session_id"] = json!("runtime-session:test-2");
            evidence.properties["source_session_id"] = json!("collector-session-2");
        }
        let second = store.import_runtime_session(&first.snapshot_id, second)?;
        let snapshot = store.load_completed_snapshot(&second.snapshot_id)?;
        assert_eq!(snapshot.sites.len(), 1);
        assert_eq!(snapshot.coverage.dependency_sites, 1);
        assert_eq!(snapshot.coverage.resolved, 1);
        assert_eq!(snapshot.coverage.candidates, 0);
        assert_eq!(snapshot.coverage.external, 0);
        assert_eq!(snapshot.coverage.unresolved, 0);
        assert_eq!(
            snapshot
                .evidence
                .iter()
                .filter(|evidence| evidence.kind == "runtime")
                .count(),
            4
        );
        Ok(())
    }

    #[test]
    fn semantic_noop_over_runtime_includes_inherited_runtime_only_nodes_in_paged_projection()
    -> Result<()> {
        let (mut store, base_snapshot_id, base) = seeded_store()?;
        let mut delta = valid_delta(&base_snapshot_id, &base);
        delta.nodes.push(NodeRecord {
            id: "runtime:only".to_owned(),
            kind: "runtime_target".to_owned(),
            locator: "runtime://only".to_owned(),
            display_name: "runtime only".to_owned(),
            properties: json!({"runtime_only": true}),
        });
        let runtime_snapshot_id = store
            .import_runtime_session(&base_snapshot_id, delta)?
            .snapshot_id;
        let runtime_snapshot = store.load_completed_snapshot(&runtime_snapshot_id)?;
        let overlay_node = runtime_snapshot
            .nodes
            .iter()
            .find(|node| node.id == "file:source")
            .context("base file node")?
            .clone();
        let semantic_scan_id = "semantic-over-runtime";
        let tx = store.connection.transaction()?;
        tx.execute(
            "INSERT INTO scans(
                id, root, status, strict, started_at, completed_at,
                project_code_executed, protocol_version, parent_snapshot_id,
                source_revision, mutation_count
             ) VALUES (?1, '/fixture', 'completed', 0,
                       '2026-08-01T00:00:00Z', '2026-08-01T00:00:01Z',
                       0, '1.0', ?2, 'runtime-semantic-revision', 1)",
            params![semantic_scan_id, runtime_snapshot_id],
        )?;
        tx.execute(
            "INSERT INTO nodes(
                scan_id, id, kind, locator, display_name, properties_json, raw_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                semantic_scan_id,
                overlay_node.id,
                overlay_node.kind,
                overlay_node.locator,
                overlay_node.display_name,
                serde_json::to_string(&overlay_node.properties)?,
                serde_json::to_string(&overlay_node)?,
            ],
        )?;
        tx.execute(
            "INSERT INTO incremental_deltas(
                scan_id, delta_id, adapter, base_snapshot_id, base_graph_digest,
                result_graph_digest, scope_json, events_json, mutation_count,
                status, prospective_snapshot_id, staged_at, completed_at
             ) VALUES (?1, 'delta:semantic-over-runtime', 'web', ?2,
                       'base-digest', 'result-digest', '{}', '[]', 1,
                       'applied', NULL, '2026-08-01T00:00:00Z',
                       '2026-08-01T00:00:01Z')",
            params![semantic_scan_id, runtime_snapshot_id],
        )?;
        let (semantic_snapshot_id, profile_ids) =
            super::super::incremental::semantic_noop_snapshot_identity(
                &tx,
                semantic_scan_id,
                &runtime_snapshot_id,
                Some("runtime-semantic-revision"),
            )?;
        tx.execute(
            "UPDATE incremental_deltas SET prospective_snapshot_id=?2 WHERE scan_id=?1",
            params![semantic_scan_id, semantic_snapshot_id],
        )?;
        tx.execute(
            "INSERT INTO completed_snapshots(
                id, source_kind, source_attempt_id, scan_id, build_attempt_id,
                runtime_import_id, runtime_session_set_json, parent_snapshot_id,
                source_revision, profile_set_json, status, created_at
             ) VALUES (?1, 'scan', ?2, ?2, NULL, NULL, '[]', ?3,
                       'runtime-semantic-revision', ?4, 'completed',
                       '2026-08-01T00:00:01Z')",
            params![
                semantic_snapshot_id,
                semantic_scan_id,
                runtime_snapshot_id,
                serde_json::to_string(&profile_ids)?,
            ],
        )?;
        super::super::persist_completed_snapshot_seal(&tx, &semantic_snapshot_id)?;
        tx.commit()?;

        let mut canonical_snapshot = store.load_completed_snapshot(&semantic_snapshot_id)?;
        let canonical = std::mem::take(&mut canonical_snapshot.nodes)
            .into_iter()
            .map(|node| super::super::NodeSummaryRecord {
                id: node.id,
                kind: node.kind,
                locator: node.locator,
                display_name: node.display_name,
            })
            .collect::<Vec<_>>();
        assert!(canonical.iter().any(|node| node.id == "runtime:only"));
        let page = store.find_completed_snapshot_nodes_page(
            &semantic_snapshot_id,
            "",
            super::super::NodeTextMatch::Contains,
            &[],
            0,
            100,
            || false,
        )?;

        assert_eq!(page.total_items, canonical.len() as u64);
        assert_eq!(page.items, canonical);
        Ok(())
    }
}
