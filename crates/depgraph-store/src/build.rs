//! Build-delta construction, validation, and merging for build attempts.
//!
//! `Store::save_build_audit` / `start_build_attempt` (and its base-snapshot
//! variants) / `save_build_delta` / `finish_build_attempt` own the full
//! lifecycle of one build-evidence attempt: recording the supervisor's
//! audit, staging an immutable attempt row, validating a `ValidatedProtocol`
//! into a `BuildGraphDelta` against the base graph, and promoting the result
//! into a new completed snapshot. The free functions alongside them build,
//! validate, deduplicate, and merge that delta. Extracted from `lib.rs`
//! (REFACTOR-001-TASK-007) as a pure move -- no logic changes. Functions
//! used only within this module stay private; `validate_build_union`,
//! `validate_delta_attempt_metadata`, `merge_build_delta`, and
//! `union_coverage` are also called from the compiler-precise cache
//! (`cache.rs`), `load_snapshot` (`lib.rs`), and validation reads
//! (`read.rs`), so they are `pub(crate)`.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use depgraph_protocol::{
    Coverage, Diagnostic, Evidence, ProtocolEvent, ValidatedProtocol, validate_build_contract,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    BuildAttemptRecord, BuildAuditRecord, BuildGraphDelta, CoverageRecord, DiagnosticRecord,
    EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, ProfileRecord, SiteRecord,
    SnapshotSource, Store, canonical_effective_input_id, create_completed_snapshot,
    declared_effective_input_id, declared_parent_profile_id, is_sha256_hex,
    load_completed_snapshot_record, promote_completed_snapshot, refresh_profile_matrix,
    required_str,
};

impl Store {
    pub fn save_build_audit(&mut self, audit: &Value) -> Result<()> {
        let object = audit
            .as_object()
            .context("build audit must be a JSON object")?;
        let run_id = required_str(audit, "run_id")?;
        let outcome = required_str(audit, "outcome")?;
        let started_at = required_str(audit, "started_at")?;
        let finished_at = required_str(audit, "finished_at")?;
        if run_id.trim().is_empty() {
            bail!("build audit run_id must not be empty");
        }
        if !matches!(
            outcome,
            "completed" | "failed" | "timed_out" | "cancelled" | "security_failed"
        ) {
            bail!("invalid build audit outcome {outcome}");
        }
        let environment_keys = object
            .get("environment_keys")
            .and_then(Value::as_array)
            .context("build audit environment_keys must be an array")?;
        for key in environment_keys {
            let key = key
                .as_str()
                .context("build audit environment key must be a string")?;
            if is_secret_like_key(key) {
                bail!("build audit contains a secret-like environment key");
            }
        }
        let raw = serde_json::to_string(audit)?;
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO build_audits(run_id, outcome, started_at, finished_at, audit_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![run_id, outcome, started_at, finished_at, raw],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn build_audit(&self, run_id: &str) -> Result<Option<BuildAuditRecord>> {
        self.connection
            .query_row(
                "SELECT run_id, outcome, started_at, finished_at, audit_json
                   FROM build_audits WHERE run_id=?1",
                [run_id],
                |row| {
                    let raw = row.get::<_, String>(4)?;
                    let audit = serde_json::from_str(&raw).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            raw.len(),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok(BuildAuditRecord {
                        run_id: row.get(0)?,
                        outcome: row.get(1)?,
                        started_at: row.get(2)?,
                        finished_at: row.get(3)?,
                        audit,
                    })
                },
            )
            .optional()
            .context("failed to load build audit")
    }

    pub fn latest_build_audit(&self) -> Result<Option<BuildAuditRecord>> {
        self.connection
            .query_row(
                "SELECT run_id, outcome, started_at, finished_at, audit_json
                   FROM build_audits ORDER BY started_at DESC, rowid DESC LIMIT 1",
                [],
                |row| {
                    let raw = row.get::<_, String>(4)?;
                    let audit = serde_json::from_str(&raw).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            raw.len(),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok(BuildAuditRecord {
                        run_id: row.get(0)?,
                        outcome: row.get(1)?,
                        started_at: row.get(2)?,
                        finished_at: row.get(3)?,
                        audit,
                    })
                },
            )
            .optional()
            .context("failed to load latest build audit")
    }

    /// Starts an immutable build-evidence attempt tied to one completed base
    /// scan and one supervisor audit. Only completed audits may later stage a
    /// graph delta; failed audits remain queryable attempt metadata.
    pub fn start_build_attempt(&mut self, base_scan_id: &str, audit: &Value) -> Result<String> {
        self.start_build_attempt_with_base_snapshot(base_scan_id, audit, None)
    }

    pub fn start_build_attempt_at_base_snapshot(
        &mut self,
        base_scan_id: &str,
        base_snapshot_id: &str,
        audit: &Value,
    ) -> Result<String> {
        self.start_build_attempt_with_base_snapshot(base_scan_id, audit, Some(base_snapshot_id))
    }

    fn start_build_attempt_with_base_snapshot(
        &mut self,
        base_scan_id: &str,
        audit: &Value,
        requested_base_snapshot_id: Option<&str>,
    ) -> Result<String> {
        let run_id = required_str(audit, "run_id")?;
        let outcome = required_str(audit, "outcome")?;
        let output_digest = audit
            .get("validated_output_digest")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        if outcome == "completed" && output_digest.is_none() {
            bail!("completed build audit must include validated_output_digest");
        }
        for (field, digest) in [
            (
                "command_plan_digest",
                required_str(audit, "command_plan_digest")?,
            ),
            (
                "toolchain_executable_digest",
                required_str(audit, "toolchain_executable_digest")?,
            ),
            (
                "environment_key_set_digest",
                required_str(audit, "environment_key_set_digest")?,
            ),
        ] {
            if !is_sha256_hex(digest) {
                bail!("build audit {field} must be a lowercase SHA-256 digest");
            }
        }
        if let Some(output_digest) = output_digest
            && !is_sha256_hex(output_digest)
        {
            bail!("build audit validated_output_digest must be a lowercase SHA-256 digest");
        }
        let stored_audit = self
            .build_audit(run_id)?
            .with_context(|| format!("build audit {run_id} must be saved before its attempt"))?;
        if stored_audit.audit != *audit {
            bail!("build attempt audit does not match the saved audit");
        }
        let base_status = self
            .scan(base_scan_id)?
            .with_context(|| format!("base scan {base_scan_id} was not found"))?
            .status;
        if base_status != "completed" {
            bail!("build evidence requires a completed base scan");
        }
        // Build profiles are additive evidence layers. A later build attempt
        // validates against the latest completed snapshot for the same safe
        // scan so it cannot silently replace an already-promoted build (or
        // runtime) layer.
        let base_snapshot_id = if let Some(snapshot_id) = requested_base_snapshot_id {
            let safe_snapshot_id = self
                .snapshot_id_for_source("scan", base_scan_id)?
                .with_context(|| format!("base scan {base_scan_id} has no safe snapshot"))?;
            if safe_snapshot_id != snapshot_id {
                bail!("requested build base snapshot is not the selected safe scan snapshot");
            }
            if !self.verify_snapshot_integrity(snapshot_id)?.valid {
                bail!("requested build base snapshot failed integrity validation");
            }
            snapshot_id.to_owned()
        } else {
            self.snapshot_id_for_scan_selection(base_scan_id)?
                .with_context(|| format!("base scan {base_scan_id} has no completed snapshot"))?
        };
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO build_attempts(
                id, base_scan_id, base_snapshot_id, audit_run_id, status, observer, observer_version,
                profile_id, command_plan_digest, toolchain_executable_digest,
                environment_key_set_digest, validated_output_digest, started_at
             ) VALUES (?1, ?2, ?3, ?4, 'staging', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                run_id,
                base_scan_id,
                base_snapshot_id,
                run_id,
                required_str(audit, "adapter")?,
                required_str(audit, "adapter_version")?,
                required_str(audit, "profile_id")?,
                required_str(audit, "command_plan_digest")?,
                required_str(audit, "toolchain_executable_digest")?,
                required_str(audit, "environment_key_set_digest")?,
                output_digest,
                required_str(audit, "started_at")?,
            ],
        )?;
        tx.commit()?;
        Ok(run_id.to_owned())
    }

    /// Atomically validates and stages a complete build delta. A rejected
    /// protocol leaves the attempt without any partial graph payload.
    pub fn save_build_delta(
        &mut self,
        attempt_id: &str,
        protocol: &ValidatedProtocol,
    ) -> Result<()> {
        validate_build_contract(protocol).context("invalid build evidence protocol")?;
        let attempt = self
            .build_attempt(attempt_id)?
            .with_context(|| format!("build attempt {attempt_id} was not found"))?;
        if attempt.status != "staging" {
            bail!(
                "build attempt {attempt_id} is immutable after reaching {}",
                attempt.status
            );
        }
        let mut delta = build_delta_from_protocol(protocol)?;
        let audit = self
            .build_audit(&attempt.audit_run_id)?
            .context("build attempt audit is missing")?;
        if audit.outcome != "completed" || attempt.validated_output_digest.is_none() {
            bail!("only a completed supervisor attempt can stage build evidence");
        }
        validate_delta_attempt_metadata(&delta, &attempt)?;
        let base_snapshot_id = attempt
            .base_snapshot_id
            .as_deref()
            .context("build attempt has no completed base snapshot")?;
        if !self.verify_snapshot_integrity(base_snapshot_id)?.valid {
            bail!("build attempt base snapshot {base_snapshot_id} failed integrity validation");
        }
        let base = self.load_completed_snapshot(base_snapshot_id)?;
        deduplicate_identical_build_evidence(&base, &mut delta)?;
        validate_build_union(&base, &delta, &attempt)?;
        let encoded = serde_json::to_string(&delta)?;
        let tx = self.connection.transaction()?;
        ensure_build_staging(&tx, attempt_id)?;
        tx.execute(
            "UPDATE build_attempts SET delta_json=?2 WHERE id=?1",
            params![attempt_id, encoded],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn finish_build_attempt(
        &mut self,
        attempt_id: &str,
        status: &str,
        error: Option<&str>,
        promote: bool,
    ) -> Result<()> {
        if !matches!(
            status,
            "completed" | "partial" | "failed" | "timed_out" | "cancelled" | "security_failed"
        ) {
            bail!("invalid terminal build attempt status {status}");
        }
        if promote && status != "completed" {
            bail!("only completed build attempts can be promoted");
        }
        let tx = self.connection.transaction()?;
        ensure_build_staging(&tx, attempt_id)?;
        let (base_scan_id, base_snapshot_id, has_delta, audit_outcome): (
            String,
            Option<String>,
            bool,
            String,
        ) = tx.query_row(
            "SELECT a.base_scan_id, a.base_snapshot_id, a.delta_json IS NOT NULL, b.outcome
               FROM build_attempts a JOIN build_audits b ON b.run_id=a.audit_run_id
              WHERE a.id=?1",
            [attempt_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if status == "completed" && !has_delta {
            bail!("completed build attempt {attempt_id} has no validated delta");
        }
        if status == "completed" && audit_outcome != "completed" {
            bail!("completed build attempt requires a completed supervisor audit");
        }
        if audit_outcome != "completed" && status != audit_outcome {
            bail!(
                "build attempt status {status} does not match supervisor outcome {audit_outcome}"
            );
        }
        let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        tx.execute(
            "UPDATE build_attempts
                SET status=?2, completed_at=?3, error=?4,
                    delta_json=CASE WHEN ?2='completed' THEN delta_json ELSE NULL END
              WHERE id=?1",
            params![attempt_id, status, completed_at, error],
        )?;
        let completed_snapshot_id = if status == "completed" {
            let attempt_base_snapshot_id = base_snapshot_id.with_context(|| {
                format!("build attempt {attempt_id} has no base completed snapshot")
            })?;
            let latest_snapshot_id = tx
                .query_row(
                    "SELECT id FROM completed_snapshots
                      WHERE scan_id=?1 AND status='completed'
                      ORDER BY julianday(created_at) DESC, rowid DESC LIMIT 1",
                    [&base_scan_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .with_context(|| format!("base scan {base_scan_id} has no completed snapshot"))?;
            let latest_snapshot = load_completed_snapshot_record(&tx, &latest_snapshot_id)?
                .context("latest completed snapshot metadata was not found")?;
            let preserve_runtime = !latest_snapshot.runtime_session_ids.is_empty();
            let parent_snapshot_id = if preserve_runtime {
                latest_snapshot.id.as_str()
            } else {
                attempt_base_snapshot_id.as_str()
            };
            let source_revision = if preserve_runtime {
                latest_snapshot.source_revision.clone()
            } else {
                tx.query_row(
                    "SELECT source_revision FROM completed_snapshots WHERE id=?1",
                    [parent_snapshot_id],
                    |row| row.get::<_, Option<String>>(0),
                )?
            };
            let runtime_session_ids = if preserve_runtime {
                latest_snapshot.runtime_session_ids.as_slice()
            } else {
                &[]
            };
            Some(create_completed_snapshot(
                &tx,
                SnapshotSource {
                    source_kind: "build",
                    source_attempt_id: attempt_id,
                    scan_id: &base_scan_id,
                    build_attempt_id: Some(attempt_id),
                    runtime_import_id: None,
                    runtime_session_ids,
                    parent_snapshot_id: Some(parent_snapshot_id),
                    source_revision: source_revision.as_deref(),
                    created_at: &completed_at,
                },
            )?)
        } else {
            None
        };
        if promote {
            let snapshot_id = completed_snapshot_id
                .as_deref()
                .context("completed build attempt did not create a snapshot")?;
            tx.execute(
                "INSERT INTO current_build_successful(base_scan_id, attempt_id) VALUES (?1, ?2)
                 ON CONFLICT(base_scan_id) DO UPDATE SET attempt_id=excluded.attempt_id",
                params![base_scan_id, attempt_id],
            )?;
            promote_completed_snapshot(&tx, snapshot_id)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn build_attempt(&self, attempt_id: &str) -> Result<Option<BuildAttemptRecord>> {
        self.connection
            .query_row(
                "SELECT id, base_scan_id, base_snapshot_id, audit_run_id, status, observer, observer_version,
                        profile_id, command_plan_digest, toolchain_executable_digest,
                        environment_key_set_digest, validated_output_digest, started_at,
                        completed_at, error
                   FROM build_attempts WHERE id=?1",
                [attempt_id],
                |row| {
                    Ok(BuildAttemptRecord {
                        id: row.get(0)?,
                        base_scan_id: row.get(1)?,
                        base_snapshot_id: row.get(2)?,
                        audit_run_id: row.get(3)?,
                        status: row.get(4)?,
                        observer: row.get(5)?,
                        observer_version: row.get(6)?,
                        profile_id: row.get(7)?,
                        command_plan_digest: row.get(8)?,
                        toolchain_executable_digest: row.get(9)?,
                        environment_key_set_digest: row.get(10)?,
                        validated_output_digest: row.get(11)?,
                        started_at: row.get(12)?,
                        completed_at: row.get(13)?,
                        error: row.get(14)?,
                    })
                },
            )
            .optional()
            .context("failed to load build attempt")
    }

    pub fn current_build_attempt_id(&self, base_scan_id: &str) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT attempt_id FROM current_build_successful WHERE base_scan_id=?1",
                [base_scan_id],
                |row| row.get(0),
            )
            .optional()
            .context("failed to load current build attempt")
    }
}

fn is_secret_like_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "AUTH",
        "COOKIE",
        "SESSION",
    ]
    .iter()
    .any(|part| upper.contains(part))
}

fn build_delta_from_protocol(protocol: &ValidatedProtocol) -> Result<BuildGraphDelta> {
    let profile_coverage = protocol
        .events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::ProfileCompleted(completed) => Some((
                completed.profile_id.clone(),
                coverage_record(&completed.coverage),
            )),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let coverage = protocol
        .events
        .iter()
        .rev()
        .find_map(|event| match event {
            ProtocolEvent::ScanCompleted(completed) => Some(coverage_record(&completed.coverage)),
            _ => None,
        })
        .context("build protocol has no final coverage")?;
    let profiles = protocol
        .profiles
        .values()
        .map(|profile| ProfileRecord {
            id: profile.id.clone(),
            language: profile.language.clone(),
            toolchain: profile.toolchain.clone(),
            command: profile.command.clone(),
            target: profile.target.clone(),
            features: profile.features.clone(),
            environment: serde_json::to_value(&profile.environment).unwrap_or_else(|_| json!({})),
            source_revision: profile.source_revision.clone(),
            properties: serde_json::to_value(&profile.properties).unwrap_or_else(|_| json!({})),
            coverage: profile_coverage.get(&profile.id).cloned(),
        })
        .collect();
    let nodes = protocol
        .nodes
        .values()
        .map(|node| NodeRecord {
            id: node.id.clone(),
            kind: node.kind.clone(),
            locator: node.locator.clone(),
            display_name: node
                .display_name
                .clone()
                .unwrap_or_else(|| node.locator.clone()),
            properties: serde_json::to_value(&node.properties).unwrap_or_else(|_| json!({})),
        })
        .collect();
    let sites = protocol
        .sites
        .values()
        .map(|site| SiteRecord {
            id: site.id.clone(),
            source: site.source.clone(),
            kind: site.kind.clone(),
            specifier: Some(site.specifier.clone()),
            profile_id: site.profile_id.clone(),
            resolution_status: enum_json(&site.resolution_status),
            precision: enum_json(&site.precision),
            condition: serde_json::to_value(&site.condition).unwrap_or_else(|_| json!({})),
            target_ids: site.target_ids.clone(),
            reason: site.reason.clone(),
        })
        .collect();
    let edges = protocol
        .edges
        .values()
        .map(|edge| EdgeRecord {
            id: edge.id.clone(),
            site_id: edge.site_id.clone(),
            source: edge.source.clone(),
            target: edge.target.clone(),
            kind: edge.kind.clone(),
            phase: enum_json(&edge.phase),
            environment: edge.environment.clone().unwrap_or_else(|| "any".to_owned()),
            profile_id: edge.profile_id.clone(),
            resolution_status: enum_json(&edge.resolution_status),
            precision: enum_json(&edge.precision),
            condition: serde_json::to_value(&edge.condition).unwrap_or_else(|_| json!({})),
            generated: edge.generated,
        })
        .collect();
    let mut evidence = Vec::new();
    for site in protocol.sites.values() {
        append_evidence_records(&mut evidence, "site", &site.id, &site.evidence)?;
    }
    for edge in protocol.edges.values() {
        append_evidence_records(&mut evidence, "edge", &edge.id, &edge.evidence)?;
    }
    let mut diagnostics = Vec::new();
    for (ordinal, diagnostic) in protocol.diagnostics.values().enumerate() {
        diagnostics.push(diagnostic_record(ordinal as i64, diagnostic));
        append_evidence_records(
            &mut evidence,
            "diagnostic",
            &diagnostic.id,
            &diagnostic.evidence,
        )?;
    }
    Ok(BuildGraphDelta {
        profiles,
        nodes,
        sites,
        edges,
        evidence,
        diagnostics,
        coverage,
    })
}

fn enum_json<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

fn coverage_record(coverage: &Coverage) -> CoverageRecord {
    CoverageRecord {
        profiles: coverage.profiles,
        files_discovered: coverage.files_discovered,
        files_analyzed: coverage.files_analyzed,
        files_skipped: coverage.files_skipped,
        dependency_sites: coverage.dependency_sites,
        resolved: coverage.resolved,
        candidates: coverage.candidates,
        external: coverage.external,
        unresolved: coverage.unresolved,
        unsupported_syntax: coverage.unsupported_syntax,
        project_code_executed: coverage.project_code_executed,
        completeness: coverage.completeness.iter().map(enum_json).collect(),
        reasons: coverage.reasons.clone(),
    }
}

fn append_evidence_records(
    output: &mut Vec<EvidenceRecord>,
    owner_type: &str,
    owner_id: &str,
    evidence: &[Evidence],
) -> Result<()> {
    for (ordinal, item) in evidence.iter().enumerate() {
        output.push(EvidenceRecord {
            owner_type: owner_type.to_owned(),
            owner_id: owner_id.to_owned(),
            ordinal: ordinal as i64,
            kind: enum_json(&item.kind),
            extractor: item.extractor.clone(),
            extractor_version: item.extractor_version.clone(),
            path: item.path.clone().unwrap_or_default(),
            start_line: item.start_line.unwrap_or(1).into(),
            start_column: item.start_column.unwrap_or(1).into(),
            end_line: item.end_line.unwrap_or(1).into(),
            end_column: item.end_column.unwrap_or(1).into(),
            detail: item.detail.clone(),
            properties: serde_json::to_value(&item.properties)?,
        });
    }
    Ok(())
}

fn diagnostic_record(ordinal: i64, diagnostic: &Diagnostic) -> DiagnosticRecord {
    DiagnosticRecord {
        ordinal,
        id: diagnostic.id.clone(),
        severity: enum_json(&diagnostic.severity),
        code: diagnostic.code.clone(),
        message: diagnostic.message.clone(),
        path: diagnostic.path.clone(),
        adapter: None,
        start_line: diagnostic.start_line.map(Into::into),
        start_column: diagnostic.start_column.map(Into::into),
        end_line: diagnostic.end_line.map(Into::into),
        end_column: diagnostic.end_column.map(Into::into),
        properties: serde_json::to_value(&diagnostic.properties).unwrap_or_else(|_| json!({})),
    }
}

pub(crate) fn validate_delta_attempt_metadata(
    delta: &BuildGraphDelta,
    attempt: &BuildAttemptRecord,
) -> Result<()> {
    let output_digest = attempt
        .validated_output_digest
        .as_deref()
        .context("build attempt has no validated output digest")?;
    for evidence in delta.evidence.iter().filter(|evidence| {
        matches!(evidence.owner_type.as_str(), "site" | "edge") && evidence.ordinal == 0
    }) {
        if evidence.kind != "build"
            || evidence.extractor != attempt.observer
            || evidence.extractor_version != attempt.observer_version
        {
            bail!("build evidence producer does not match its attempt audit");
        }
        for (field, expected) in [
            ("build_run_id", attempt.id.as_str()),
            ("profile_id", attempt.profile_id.as_str()),
            ("command_plan_digest", attempt.command_plan_digest.as_str()),
            (
                "toolchain_executable_digest",
                attempt.toolchain_executable_digest.as_str(),
            ),
            (
                "environment_key_set_digest",
                attempt.environment_key_set_digest.as_str(),
            ),
            ("validated_output_digest", output_digest),
        ] {
            if evidence.properties.get(field).and_then(Value::as_str) != Some(expected) {
                bail!("build evidence {field} does not match its attempt audit");
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_build_union(
    base: &GraphSnapshot,
    delta: &BuildGraphDelta,
    attempt: &BuildAttemptRecord,
) -> Result<()> {
    if delta.profiles.len() != 1 || delta.profiles[0].id != attempt.profile_id {
        bail!("build delta must contain exactly its audited profile");
    }
    let base_profiles = base
        .profiles
        .iter()
        .map(|profile| (&profile.id, profile))
        .collect::<BTreeMap<_, _>>();
    for profile in &delta.profiles {
        if profile
            .properties
            .get("profile_phase")
            .and_then(Value::as_str)
            != Some("build")
        {
            bail!(
                "build profile {} must declare profile_phase=build",
                profile.id
            );
        }
        let parent_id = declared_parent_profile_id(profile)
            .with_context(|| format!("build profile {} has no parent profile", profile.id))?;
        let parent = base
            .profiles
            .iter()
            .find(|candidate| candidate.id == parent_id)
            .with_context(|| {
                format!(
                    "build profile {} parent {parent_id} is not in the base graph",
                    profile.id
                )
            })?;
        let declared_effective = declared_effective_input_id(profile).with_context(|| {
            format!(
                "build profile {} has no canonical effective input identity",
                profile.id
            )
        })?;
        if declared_effective != canonical_effective_input_id(parent)
            || canonical_profile_language(&profile.language)
                != canonical_profile_language(&parent.language)
        {
            bail!(
                "build profile {} effective parent contract is invalid",
                profile.id
            );
        }
        if let Some(existing) = base_profiles.get(&profile.id)
            && (existing.language != profile.language
                || existing.toolchain != profile.toolchain
                || existing.command != profile.command
                || existing.target != profile.target
                || existing.features != profile.features
                || existing.environment != profile.environment
                || existing.source_revision != profile.source_revision)
        {
            bail!("build profile {} conflicts with the base graph", profile.id);
        }
    }

    let base_nodes = base
        .nodes
        .iter()
        .map(|node| (&node.id, node))
        .collect::<BTreeMap<_, _>>();
    for node in &delta.nodes {
        if let Some(existing) = base_nodes.get(&node.id) {
            if *existing != node {
                bail!("build node {} would overwrite the base graph", node.id);
            }
        } else {
            let provenance = node
                .properties
                .get("build_provenance")
                .and_then(Value::as_object)
                .with_context(|| format!("new build node {} lacks build provenance", node.id))?;
            if node
                .properties
                .get("build_generated")
                .and_then(Value::as_bool)
                != Some(true)
                || provenance.get("build_run_id").and_then(Value::as_str)
                    != Some(attempt.id.as_str())
                || provenance.get("profile_id").and_then(Value::as_str)
                    != Some(attempt.profile_id.as_str())
                || provenance.get("observer").and_then(Value::as_str)
                    != Some(attempt.observer.as_str())
                || provenance.get("observer_version").and_then(Value::as_str)
                    != Some(attempt.observer_version.as_str())
                || provenance
                    .get("command_plan_digest")
                    .and_then(Value::as_str)
                    != Some(attempt.command_plan_digest.as_str())
                || provenance
                    .get("toolchain_executable_digest")
                    .and_then(Value::as_str)
                    != Some(attempt.toolchain_executable_digest.as_str())
                || provenance
                    .get("environment_key_set_digest")
                    .and_then(Value::as_str)
                    != Some(attempt.environment_key_set_digest.as_str())
                || provenance
                    .get("validated_output_digest")
                    .and_then(Value::as_str)
                    != attempt.validated_output_digest.as_deref()
            {
                bail!("new build node {} has unauthorized provenance", node.id);
            }
        }
    }
    let node_ids = base
        .nodes
        .iter()
        .chain(delta.nodes.iter())
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    let profile_ids = base
        .profiles
        .iter()
        .chain(delta.profiles.iter())
        .map(|profile| profile.id.as_str())
        .collect::<BTreeSet<_>>();
    let base_site_ids = base
        .sites
        .iter()
        .map(|site| site.id.as_str())
        .collect::<BTreeSet<_>>();
    let base_edge_ids = base
        .edges
        .iter()
        .map(|edge| edge.id.as_str())
        .collect::<BTreeSet<_>>();
    for site in &delta.sites {
        if base_site_ids.contains(site.id.as_str()) {
            bail!(
                "build site {} would overwrite an existing evidence layer",
                site.id
            );
        }
        if site.precision != "observed"
            || !node_ids.contains(site.source.as_str())
            || site
                .target_ids
                .iter()
                .any(|target| !node_ids.contains(target.as_str()))
            || !profile_ids.contains(site.profile_id.as_str())
        {
            bail!("build site {} is not authorized by the base graph", site.id);
        }
    }
    let delta_site_ids = delta
        .sites
        .iter()
        .map(|site| site.id.as_str())
        .collect::<BTreeSet<_>>();
    for edge in &delta.edges {
        if base_edge_ids.contains(edge.id.as_str()) {
            bail!(
                "build edge {} would overwrite an existing evidence layer",
                edge.id
            );
        }
        if edge.phase != "build"
            || edge.precision != "observed"
            || !node_ids.contains(edge.source.as_str())
            || !node_ids.contains(edge.target.as_str())
            || !profile_ids.contains(edge.profile_id.as_str())
            || edge
                .site_id
                .as_deref()
                .is_some_and(|site_id| !delta_site_ids.contains(site_id))
        {
            bail!("build edge {} is not authorized by the base graph", edge.id);
        }
    }
    Ok(())
}

fn deduplicate_identical_build_evidence(
    base: &GraphSnapshot,
    delta: &mut BuildGraphDelta,
) -> Result<()> {
    let base_sites = base
        .sites
        .iter()
        .map(|site| (site.id.as_str(), site))
        .collect::<BTreeMap<_, _>>();
    let base_edges = base
        .edges
        .iter()
        .map(|edge| (edge.id.as_str(), edge))
        .collect::<BTreeMap<_, _>>();
    let mut removed_sites = Vec::new();
    for site in &delta.sites {
        if let Some(existing) = base_sites.get(site.id.as_str()) {
            if *existing != site {
                bail!(
                    "build site {} conflicts with an existing evidence layer",
                    site.id
                );
            }
            removed_sites.push(site.clone());
        }
    }
    let removed_site_ids = removed_sites
        .iter()
        .map(|site| site.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut removed_edge_ids = BTreeSet::new();
    for edge in &delta.edges {
        if let Some(existing) = base_edges.get(edge.id.as_str()) {
            if *existing != edge {
                bail!(
                    "build edge {} conflicts with an existing evidence layer",
                    edge.id
                );
            }
            removed_edge_ids.insert(edge.id.clone());
        } else if edge
            .site_id
            .as_deref()
            .is_some_and(|site_id| removed_site_ids.contains(site_id))
        {
            bail!(
                "build site {} is already complete but edge {} is missing from its evidence layer",
                edge.site_id.as_deref().unwrap_or_default(),
                edge.id
            );
        }
    }
    if removed_sites.is_empty() && removed_edge_ids.is_empty() {
        return Ok(());
    }
    delta
        .sites
        .retain(|site| !removed_site_ids.contains(site.id.as_str()));
    delta
        .edges
        .retain(|edge| !removed_edge_ids.contains(&edge.id));
    delta.evidence.retain(|evidence| {
        !((evidence.owner_type == "site" && removed_site_ids.contains(evidence.owner_id.as_str()))
            || (evidence.owner_type == "edge"
                && removed_edge_ids.contains(evidence.owner_id.as_str())))
    });
    subtract_site_coverage(&mut delta.coverage, &removed_sites);
    for profile in &mut delta.profiles {
        if let Some(coverage) = &mut profile.coverage {
            let removed = removed_sites
                .iter()
                .filter(|site| site.profile_id == profile.id)
                .cloned()
                .collect::<Vec<_>>();
            subtract_site_coverage(coverage, &removed);
        }
    }
    Ok(())
}

fn subtract_site_coverage(coverage: &mut CoverageRecord, sites: &[SiteRecord]) {
    coverage.dependency_sites = coverage
        .dependency_sites
        .saturating_sub(sites.len().try_into().unwrap_or(u64::MAX));
    for site in sites {
        let counter = match site.resolution_status.as_str() {
            "resolved" => &mut coverage.resolved,
            "candidates" => &mut coverage.candidates,
            "external" => &mut coverage.external,
            "unresolved" => &mut coverage.unresolved,
            _ => continue,
        };
        *counter = counter.saturating_sub(1);
    }
    if coverage.dependency_sites == 0 {
        coverage.unsupported_syntax = 0;
        coverage.reasons.clear();
    }
}

fn canonical_profile_language(language: &str) -> &str {
    match language {
        "typescript" | "javascript" | "web" => "web",
        other => other,
    }
}

pub(crate) fn merge_build_delta(
    snapshot: &mut GraphSnapshot,
    delta: BuildGraphDelta,
    _attempt_id: &str,
) -> Result<()> {
    for profile in delta.profiles {
        if let Some(existing) = snapshot
            .profiles
            .iter_mut()
            .find(|item| item.id == profile.id)
        {
            if let Some(build_coverage) = profile.coverage {
                let coverage = existing
                    .coverage
                    .get_or_insert_with(CoverageRecord::default);
                union_coverage(coverage, &build_coverage);
            }
        } else {
            snapshot.profiles.push(profile);
        }
    }
    for node in delta.nodes {
        if !snapshot.nodes.iter().any(|item| item.id == node.id) {
            snapshot.nodes.push(node);
        }
    }
    snapshot.sites.extend(delta.sites.iter().cloned());
    snapshot.edges.extend(delta.edges);
    snapshot.evidence.extend(delta.evidence);
    snapshot.diagnostics.extend(delta.diagnostics);
    union_coverage(&mut snapshot.coverage, &delta.coverage);
    snapshot.coverage.profiles = snapshot.profiles.len() as u64;
    snapshot.scan.project_code_executed = true;
    snapshot
        .profiles
        .sort_by(|left, right| left.id.cmp(&right.id));
    snapshot.nodes.sort_by(|left, right| left.id.cmp(&right.id));
    snapshot.sites.sort_by(|left, right| left.id.cmp(&right.id));
    snapshot.edges.sort_by(|left, right| left.id.cmp(&right.id));
    refresh_profile_matrix(snapshot, true);
    Ok(())
}

pub(crate) fn union_coverage(target: &mut CoverageRecord, delta: &CoverageRecord) {
    target.dependency_sites = target
        .dependency_sites
        .saturating_add(delta.dependency_sites);
    target.resolved = target.resolved.saturating_add(delta.resolved);
    target.candidates = target.candidates.saturating_add(delta.candidates);
    target.external = target.external.saturating_add(delta.external);
    target.unresolved = target.unresolved.saturating_add(delta.unresolved);
    target.unsupported_syntax = target
        .unsupported_syntax
        .saturating_add(delta.unsupported_syntax);
    target.project_code_executed |= delta.project_code_executed;
    target
        .completeness
        .extend(delta.completeness.iter().cloned());
    target.completeness.sort();
    target.completeness.dedup();
    target.reasons.extend(delta.reasons.iter().cloned());
    target.reasons.sort();
    target.reasons.dedup();
}

fn ensure_build_staging(tx: &Transaction<'_>, attempt_id: &str) -> Result<()> {
    let status = tx
        .query_row(
            "SELECT status FROM build_attempts WHERE id=?1",
            [attempt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .with_context(|| format!("build attempt {attempt_id} was not found"))?;
    if status != "staging" {
        bail!("build attempt {attempt_id} is immutable after reaching status {status}");
    }
    Ok(())
}
