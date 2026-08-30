//! Row loaders and summary-aggregation queries for a single scan.
//!
//! These are pure data-access helpers: given a `&Connection` and a
//! `scan_id`, they materialize normalized rows into the crate's record
//! types. Extracted from `lib.rs` (REFACTOR-001-TASK-004) as a pure move —
//! no logic changes. Functions and types that are only used by other
//! functions in this module stay module-private; the ones lib.rs and
//! sibling modules (e.g. `cache`) call across module boundaries are
//! `pub(crate)`.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::{
    AdapterLogRecord, AdapterLogSummaryRecord, CoverageRecord, DOCTOR_EFFECTIVE_DIAGNOSTICS_CTE,
    DOCTOR_OVERLAY_LAYERS_CTE, DOCTOR_SUMMARY_MAX_DIAGNOSTIC_GROUPS,
    DOCTOR_SUMMARY_MAX_DIAGNOSTIC_SAMPLES, DOCTOR_SUMMARY_MAX_KEY_BYTES,
    DOCTOR_SUMMARY_MAX_TEXT_BYTES, DiagnosticGroupSummaryRecord, DiagnosticRecord,
    DiagnosticSampleSummaryRecord, DiagnosticSummaryRecord, EdgeRecord, EvidenceRecord,
    FileCoverageRecord, FileCoverageSummaryRecord, GraphSnapshot, GraphTopology, GraphTopologyEdge,
    GraphTopologyNode, NodeRecord, ProfileRecord, ScanAttemptSummaryRecord, ScanRecord, SiteRecord,
    required_str, runtime, union_coverage,
};

pub(crate) fn load_scan_attempt_summary(
    connection: &Connection,
    scan_id: &str,
) -> Result<ScanAttemptSummaryRecord> {
    let mut scan = connection
        .query_row(
            "SELECT id, root, status, strict, started_at, completed_at,
                    project_code_executed, error, parent_snapshot_id, source_revision
               FROM scans WHERE id=?1",
            [scan_id],
            |row| {
                Ok(ScanRecord {
                    id: row.get(0)?,
                    root: row.get(1)?,
                    status: row.get(2)?,
                    strict: row.get(3)?,
                    started_at: row.get(4)?,
                    completed_at: row.get(5)?,
                    project_code_executed: row.get(6)?,
                    error: row.get(7)?,
                    parent_snapshot_id: row.get(8)?,
                    source_revision: row.get(9)?,
                })
            },
        )
        .optional()?
        .with_context(|| format!("scan {scan_id} was not found"))?;
    let (profile_count, profiles_by_language) =
        load_effective_profile_summary(connection, scan_id)?;

    let stored_coverage = connection
        .query_row(
            "SELECT json FROM coverage WHERE scan_id=?1",
            [scan_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|raw| serde_json::from_str::<CoverageRecord>(&raw))
        .transpose()?;
    let mut coverage = stored_coverage.unwrap_or_else(|| CoverageRecord {
        reasons: vec!["final worker coverage unavailable".to_owned()],
        ..CoverageRecord::default()
    });
    coverage.project_code_executed = scan.project_code_executed;
    for build_coverage in load_doctor_build_coverages(connection, scan_id)? {
        union_coverage(&mut coverage, &build_coverage);
    }
    for runtime_coverage in load_doctor_runtime_coverages(connection, scan_id)? {
        runtime::union_runtime_coverage_metadata(&mut coverage, &runtime_coverage);
    }
    let (dependency_sites, resolved, candidates, external, unresolved) =
        load_effective_site_summary(connection, scan_id)?;
    coverage.profiles = profile_count;
    coverage.dependency_sites = dependency_sites;
    coverage.resolved = resolved;
    coverage.candidates = candidates;
    coverage.external = external;
    coverage.unresolved = unresolved;
    scan.project_code_executed = coverage.project_code_executed;

    let package_instance_count = load_effective_package_instance_count(connection, scan_id)?;
    let mut file_statement = connection.prepare(
        "SELECT adapter, COUNT(*),
                COALESCE(SUM(CASE WHEN skipped THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(discovered_sites), 0),
                COALESCE(SUM(emitted_sites), 0),
                COALESCE(SUM(skipped_sites), 0)
           FROM file_coverage
          WHERE scan_id=?1
          GROUP BY adapter
          ORDER BY adapter",
    )?;
    let file_coverage = file_statement
        .query_map([scan_id], |row| {
            Ok(FileCoverageSummaryRecord {
                adapter: row.get(0)?,
                files: row.get(1)?,
                skipped_files: row.get(2)?,
                discovered_sites: row.get(3)?,
                emitted_sites: row.get(4)?,
                skipped_sites: row.get(5)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut log_statement = connection.prepare(
        "SELECT adapter, length(CAST(stderr AS BLOB)), truncated
           FROM adapter_logs
          WHERE scan_id=?1
          ORDER BY adapter",
    )?;
    let adapter_logs = log_statement
        .query_map([scan_id], |row| {
            Ok(AdapterLogSummaryRecord {
                adapter: row.get(0)?,
                stderr_bytes: row.get(1)?,
                truncated: row.get(2)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(ScanAttemptSummaryRecord {
        scan,
        coverage,
        profile_count,
        profiles_by_language,
        package_instance_count,
        file_coverage,
        adapter_logs,
        diagnostics: load_diagnostic_summary(connection, scan_id)?,
    })
}

fn load_effective_profile_summary(
    connection: &Connection,
    scan_id: &str,
) -> Result<(u64, BTreeMap<String, u64>)> {
    let sql = format!(
        "{DOCTOR_OVERLAY_LAYERS_CTE},
effective_profiles(id, language) AS (
    SELECT id, json_extract(json, '$.language')
      FROM profiles
     WHERE scan_id=?1
    UNION
    SELECT json_extract(item.value, '$.id'),
           json_extract(item.value, '$.language')
      FROM build_layers AS layers
      JOIN build_attempts AS attempts ON attempts.id=layers.build_attempt_id
      JOIN json_each(attempts.delta_json, '$.profiles') AS item
     WHERE attempts.status='completed' AND attempts.delta_json IS NOT NULL
    UNION
    SELECT json_extract(session.profile_json, '$.id'),
           json_extract(session.profile_json, '$.language')
      FROM runtime_layers AS layers
      JOIN runtime_sessions AS session ON session.id=layers.session_id
),
deduplicated_profiles(id, language) AS (
    SELECT id, MIN(language)
      FROM effective_profiles
     GROUP BY id
)
SELECT language, COUNT(*)
  FROM deduplicated_profiles
 GROUP BY language
 ORDER BY language"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
    })?;
    let mut profile_count = 0_u64;
    let mut profiles_by_language = BTreeMap::new();
    for row in rows {
        let (language, count) = row?;
        profile_count = profile_count.saturating_add(count);
        profiles_by_language.insert(language, count);
    }
    Ok((profile_count, profiles_by_language))
}

fn load_effective_package_instance_count(connection: &Connection, scan_id: &str) -> Result<u64> {
    let sql = format!(
        "{DOCTOR_OVERLAY_LAYERS_CTE},
effective_package_instances(id) AS (
    SELECT id
      FROM nodes
     WHERE scan_id=?1 AND kind='package_instance'
    UNION
    SELECT json_extract(item.value, '$.id')
      FROM build_layers AS layers
      JOIN build_attempts AS attempts ON attempts.id=layers.build_attempt_id
      JOIN json_each(attempts.delta_json, '$.nodes') AS item
     WHERE attempts.status='completed'
       AND attempts.delta_json IS NOT NULL
       AND json_extract(item.value, '$.kind')='package_instance'
    UNION
    SELECT json_extract(node.raw_json, '$.id')
      FROM runtime_layers AS layers
      JOIN runtime_nodes AS node ON node.session_id=layers.session_id
     WHERE json_extract(node.raw_json, '$.kind')='package_instance'
)
SELECT COUNT(DISTINCT id) FROM effective_package_instances"
    );
    connection
        .query_row(&sql, [scan_id], |row| row.get(0))
        .map_err(Into::into)
}

fn load_doctor_build_coverages(
    connection: &Connection,
    scan_id: &str,
) -> Result<Vec<CoverageRecord>> {
    let sql = format!(
        "{DOCTOR_OVERLAY_LAYERS_CTE}
SELECT json_extract(attempts.delta_json, '$.coverage')
  FROM build_layers AS layers
  JOIN build_attempts AS attempts ON attempts.id=layers.build_attempt_id
 WHERE attempts.status='completed' AND attempts.delta_json IS NOT NULL
 ORDER BY layers.depth DESC, attempts.id"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map([scan_id], |row| row.get::<_, String>(0))?;
    rows.map(|raw| Ok(serde_json::from_str(&raw?)?)).collect()
}

fn load_doctor_runtime_coverages(
    connection: &Connection,
    scan_id: &str,
) -> Result<Vec<CoverageRecord>> {
    let sql = format!(
        "{DOCTOR_OVERLAY_LAYERS_CTE}
SELECT session.coverage_json
  FROM runtime_layers AS layers
  JOIN runtime_sessions AS session ON session.id=layers.session_id
 ORDER BY layers.session_id"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map([scan_id], |row| row.get::<_, String>(0))?;
    rows.map(|raw| Ok(serde_json::from_str(&raw?)?)).collect()
}

fn load_effective_site_summary(
    connection: &Connection,
    scan_id: &str,
) -> Result<(u64, u64, u64, u64, u64)> {
    let sql = format!(
        "{DOCTOR_OVERLAY_LAYERS_CTE},
site_candidates(id, resolution_status) AS (
    SELECT id, resolution_status
      FROM sites
     WHERE scan_id=?1
    UNION
    SELECT json_extract(item.value, '$.id'),
           json_extract(item.value, '$.resolution_status')
      FROM build_layers AS layers
      JOIN build_attempts AS attempts ON attempts.id=layers.build_attempt_id
      JOIN json_each(attempts.delta_json, '$.sites') AS item
     WHERE attempts.status='completed' AND attempts.delta_json IS NOT NULL
    UNION
    SELECT json_extract(site.raw_json, '$.id'),
           json_extract(site.raw_json, '$.resolution_status')
      FROM runtime_layers AS layers
      JOIN runtime_sites AS site ON site.session_id=layers.session_id
),
effective_sites(id, resolution_status) AS (
    SELECT id, MIN(resolution_status)
      FROM site_candidates
     GROUP BY id
)
SELECT COUNT(*),
       COALESCE(SUM(CASE WHEN resolution_status='resolved' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN resolution_status='candidates' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN resolution_status='external' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN resolution_status='unresolved' THEN 1 ELSE 0 END), 0)
  FROM effective_sites"
    );
    connection
        .query_row(&sql, [scan_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .map_err(Into::into)
}

fn load_diagnostic_summary(
    connection: &Connection,
    scan_id: &str,
) -> Result<DiagnosticSummaryRecord> {
    let effective_diagnostics =
        format!("{DOCTOR_OVERLAY_LAYERS_CTE}{DOCTOR_EFFECTIVE_DIAGNOSTICS_CTE}");
    let total_sql = format!("{effective_diagnostics} SELECT COUNT(*) FROM effective_diagnostics");
    let total = connection.query_row(&total_sql, [scan_id], |row| row.get::<_, u64>(0))?;
    let group_count_sql = format!(
        "{effective_diagnostics}
SELECT COUNT(*) FROM (
    SELECT 1
      FROM effective_diagnostics
     GROUP BY severity, code, adapter
)"
    );
    let raw_group_count =
        connection.query_row(&group_count_sql, [scan_id], |row| row.get::<_, u64>(0))?;
    let groups_sql = format!(
        "{effective_diagnostics}
SELECT severity, code, adapter, COUNT(*) AS diagnostic_count
  FROM effective_diagnostics
 GROUP BY severity, code, adapter
 ORDER BY diagnostic_count DESC, severity, code, COALESCE(adapter, '')
 LIMIT ?2"
    );
    let mut statement = connection.prepare(&groups_sql)?;
    let groups = statement
        .query_map(
            params![
                scan_id,
                i64::try_from(DOCTOR_SUMMARY_MAX_DIAGNOSTIC_GROUPS).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok(DiagnosticGroupSummaryRecord {
                    severity: bounded_summary_text(
                        &row.get::<_, String>(0)?,
                        DOCTOR_SUMMARY_MAX_KEY_BYTES,
                    ),
                    code: bounded_summary_text(
                        &row.get::<_, String>(1)?,
                        DOCTOR_SUMMARY_MAX_KEY_BYTES,
                    ),
                    adapter: row
                        .get::<_, Option<String>>(2)?
                        .map(|value| bounded_summary_text(&value, DOCTOR_SUMMARY_MAX_KEY_BYTES)),
                    count: row.get(3)?,
                })
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let retained_diagnostics = groups
        .iter()
        .map(|group: &DiagnosticGroupSummaryRecord| group.count)
        .sum::<u64>();

    let samples_sql = format!(
        "{effective_diagnostics}
SELECT id, severity, code, message, path, adapter
  FROM effective_diagnostics
 ORDER BY source_rank, layer_depth DESC, ordinal, id
 LIMIT ?2"
    );
    let mut sample_statement = connection.prepare(&samples_sql)?;
    let samples = sample_statement
        .query_map(
            params![
                scan_id,
                i64::try_from(DOCTOR_SUMMARY_MAX_DIAGNOSTIC_SAMPLES).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok(DiagnosticSampleSummaryRecord {
                    id: bounded_summary_text(
                        &row.get::<_, String>(0)?,
                        DOCTOR_SUMMARY_MAX_KEY_BYTES,
                    ),
                    severity: bounded_summary_text(
                        &row.get::<_, String>(1)?,
                        DOCTOR_SUMMARY_MAX_KEY_BYTES,
                    ),
                    code: bounded_summary_text(
                        &row.get::<_, String>(2)?,
                        DOCTOR_SUMMARY_MAX_KEY_BYTES,
                    ),
                    message: bounded_summary_text(
                        &row.get::<_, String>(3)?,
                        DOCTOR_SUMMARY_MAX_TEXT_BYTES,
                    ),
                    path: row
                        .get::<_, Option<String>>(4)?
                        .map(|value| bounded_summary_text(&value, DOCTOR_SUMMARY_MAX_TEXT_BYTES)),
                    adapter: row
                        .get::<_, Option<String>>(5)?
                        .map(|value| bounded_summary_text(&value, DOCTOR_SUMMARY_MAX_KEY_BYTES)),
                })
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(DiagnosticSummaryRecord {
        total,
        groups,
        omitted_groups: raw_group_count.saturating_sub(DOCTOR_SUMMARY_MAX_DIAGNOSTIC_GROUPS as u64),
        omitted_diagnostics: total.saturating_sub(retained_diagnostics),
        samples,
    })
}

fn bounded_summary_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut result = String::new();
    for character in value.chars() {
        if result.len() + character.len_utf8() > max_bytes {
            break;
        }
        result.push(character);
    }
    result
}

pub(crate) fn load_profiles(connection: &Connection, scan_id: &str) -> Result<Vec<ProfileRecord>> {
    let mut statement = connection.prepare(
        "SELECT p.json, pc.json
           FROM profiles p
           LEFT JOIN profile_coverage pc
             ON pc.scan_id=p.scan_id AND pc.profile_id=p.id
          WHERE p.scan_id=?1 ORDER BY p.id",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    rows.map(|row| {
        let (raw, raw_coverage) = row?;
        let value: Value = serde_json::from_str(&raw)?;
        Ok(ProfileRecord {
            id: required_str(&value, "id")?.to_owned(),
            language: required_str(&value, "language")?.to_owned(),
            toolchain: value.get("toolchain").cloned(),
            command: value
                .get("command")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            target: value
                .get("target")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            features: value
                .get("features")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
            environment: value
                .get("environment")
                .cloned()
                .unwrap_or_else(|| json!({})),
            source_revision: value
                .get("source_revision")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            properties: value
                .get("properties")
                .cloned()
                .unwrap_or_else(|| json!({})),
            coverage: raw_coverage
                .map(|coverage| serde_json::from_str(&coverage))
                .transpose()?,
        })
    })
    .collect()
}

pub(crate) fn load_nodes(connection: &Connection, scan_id: &str) -> Result<Vec<NodeRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, kind, locator, display_name, properties_json FROM nodes
         WHERE scan_id=?1 ORDER BY id",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        let properties: String = row.get(4)?;
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            properties,
        ))
    })?;
    rows.map(|row| {
        let (id, kind, locator, display_name, properties) = row?;
        Ok(NodeRecord {
            id,
            kind,
            locator,
            display_name,
            properties: serde_json::from_str(&properties)?,
        })
    })
    .collect()
}

pub(crate) fn load_scan_topology(connection: &Connection, scan_id: &str) -> Result<GraphTopology> {
    let mut node_statement =
        connection.prepare("SELECT id, kind FROM nodes WHERE scan_id=?1 ORDER BY id")?;
    let nodes = node_statement
        .query_map([scan_id], |row| {
            Ok(GraphTopologyNode {
                id: row.get(0)?,
                kind: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut edge_statement =
        connection.prepare("SELECT source, target FROM edges WHERE scan_id=?1 ORDER BY id")?;
    let edges = edge_statement
        .query_map([scan_id], |row| {
            Ok(GraphTopologyEdge {
                source: row.get(0)?,
                target: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(GraphTopology { nodes, edges })
}

pub(crate) fn topology_from_snapshot(snapshot: GraphSnapshot) -> GraphTopology {
    GraphTopology {
        nodes: snapshot
            .nodes
            .into_iter()
            .map(|node| GraphTopologyNode {
                id: node.id,
                kind: node.kind,
            })
            .collect(),
        edges: snapshot
            .edges
            .into_iter()
            .map(|edge| GraphTopologyEdge {
                source: edge.source,
                target: edge.target,
            })
            .collect(),
    }
}

pub(crate) fn load_sites(connection: &Connection, scan_id: &str) -> Result<Vec<SiteRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, source, kind, specifier, profile_id, resolution_status, precision,
                condition_json, target_ids_json, reason
         FROM sites WHERE scan_id=?1 ORDER BY id",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;
    rows.map(|row| {
        let (
            id,
            source,
            kind,
            specifier,
            profile_id,
            status,
            precision,
            condition,
            targets,
            reason,
        ) = row?;
        Ok(SiteRecord {
            id,
            source,
            kind,
            specifier,
            profile_id,
            resolution_status: status,
            precision,
            condition: serde_json::from_str(&condition)?,
            target_ids: serde_json::from_str(&targets)?,
            reason,
        })
    })
    .collect()
}

pub(crate) struct SiteValidationRecord {
    pub(crate) id: String,
    pub(crate) source: String,
    pub(crate) profile_id: String,
    pub(crate) resolution_status: String,
    pub(crate) precision: String,
    pub(crate) target_ids: Vec<String>,
}

pub(crate) fn load_site_validation_records(
    connection: &Connection,
    scan_id: &str,
) -> Result<Vec<SiteValidationRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, source, profile_id, resolution_status, precision, target_ids_json
         FROM sites WHERE scan_id=?1 ORDER BY id",
    )?;
    statement
        .query_map([scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .map(|row| {
            let (id, source, profile_id, resolution_status, precision, target_ids) = row?;
            Ok(SiteValidationRecord {
                id,
                source,
                profile_id,
                resolution_status,
                precision,
                target_ids: serde_json::from_str(&target_ids)?,
            })
        })
        .collect()
}

pub(crate) struct EdgeValidationRecord {
    pub(crate) id: String,
    pub(crate) site_id: Option<String>,
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) profile_id: String,
    pub(crate) resolution_status: String,
    pub(crate) precision: String,
}

pub(crate) fn load_edge_validation_records(
    connection: &Connection,
    scan_id: &str,
) -> Result<Vec<EdgeValidationRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, site_id, source, target, profile_id, resolution_status, precision
         FROM edges WHERE scan_id=?1 ORDER BY id",
    )?;
    statement
        .query_map([scan_id], |row| {
            Ok(EdgeValidationRecord {
                id: row.get(0)?,
                site_id: row.get(1)?,
                source: row.get(2)?,
                target: row.get(3)?,
                profile_id: row.get(4)?,
                resolution_status: row.get(5)?,
                precision: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub(crate) fn load_edges(connection: &Connection, scan_id: &str) -> Result<Vec<EdgeRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, site_id, source, target, kind, phase, environment, profile_id,
                resolution_status, precision, condition_json, generated
         FROM edges WHERE scan_id=?1 ORDER BY id",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, String>(10)?,
            row.get::<_, bool>(11)?,
        ))
    })?;
    rows.map(|row| {
        let (
            id,
            site_id,
            source,
            target,
            kind,
            phase,
            environment,
            profile_id,
            status,
            precision,
            condition,
            generated,
        ) = row?;
        Ok(EdgeRecord {
            id,
            site_id,
            source,
            target,
            kind,
            phase,
            environment,
            profile_id,
            resolution_status: status,
            precision,
            condition: serde_json::from_str(&condition)?,
            generated,
        })
    })
    .collect()
}

pub(crate) fn load_evidence(connection: &Connection, scan_id: &str) -> Result<Vec<EvidenceRecord>> {
    let mut statement = connection.prepare(
        "SELECT owner_type, owner_id, ordinal, kind, extractor, extractor_version, path,
                start_line, start_column, end_line, end_column, raw_json
         FROM evidence WHERE scan_id=?1 ORDER BY owner_type, owner_id, ordinal",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, u64>(7)?,
            row.get::<_, u64>(8)?,
            row.get::<_, u64>(9)?,
            row.get::<_, u64>(10)?,
            row.get::<_, String>(11)?,
        ))
    })?;
    rows.map(|row| {
        let (
            owner_type,
            owner_id,
            ordinal,
            kind,
            extractor,
            extractor_version,
            path,
            start_line,
            start_column,
            end_line,
            end_column,
            raw,
        ) = row?;
        let value: Value = serde_json::from_str(&raw)?;
        Ok(EvidenceRecord {
            owner_type,
            owner_id,
            ordinal,
            kind,
            extractor,
            extractor_version,
            path,
            start_line,
            start_column,
            end_line,
            end_column,
            detail: value
                .get("detail")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            properties: value
                .get("properties")
                .cloned()
                .unwrap_or_else(|| json!({})),
        })
    })
    .collect()
}

pub(crate) fn load_diagnostics(
    connection: &Connection,
    scan_id: &str,
) -> Result<Vec<DiagnosticRecord>> {
    let mut statement = connection.prepare(
        "SELECT ordinal, id, severity, code, message, path, adapter, raw_json
         FROM diagnostics WHERE scan_id=?1 ORDER BY ordinal",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, String>(7)?,
        ))
    })?;
    rows.map(|row| {
        let (ordinal, id, severity, code, message, path, adapter, raw) = row?;
        let value: Value = serde_json::from_str(&raw)?;
        Ok(DiagnosticRecord {
            ordinal,
            id,
            severity,
            code,
            message,
            path,
            adapter,
            start_line: value.get("start_line").and_then(Value::as_u64),
            start_column: value.get("start_column").and_then(Value::as_u64),
            end_line: value.get("end_line").and_then(Value::as_u64),
            end_column: value.get("end_column").and_then(Value::as_u64),
            properties: value
                .get("properties")
                .cloned()
                .unwrap_or_else(|| json!({})),
        })
    })
    .collect()
}

pub(crate) fn load_file_coverage(
    connection: &Connection,
    scan_id: &str,
) -> Result<Vec<FileCoverageRecord>> {
    let mut statement = connection.prepare(
        "SELECT adapter, path, discovered_sites, emitted_sites, skipped_sites, skipped, reason
           FROM file_coverage WHERE scan_id=?1 ORDER BY adapter, path",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok(FileCoverageRecord {
            adapter: row.get(0)?,
            path: row.get(1)?,
            discovered_sites: row.get(2)?,
            emitted_sites: row.get(3)?,
            skipped_sites: row.get(4)?,
            skipped: row.get(5)?,
            reason: row.get(6)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub(crate) fn load_adapter_logs(
    connection: &Connection,
    scan_id: &str,
) -> Result<Vec<AdapterLogRecord>> {
    let mut statement = connection.prepare(
        "SELECT adapter, stderr, truncated FROM adapter_logs WHERE scan_id=?1 ORDER BY adapter",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok(AdapterLogRecord {
            adapter: row.get(0)?,
            stderr: row.get(1)?,
            truncated: row.get(2)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub(crate) fn observed_coverage(
    connection: &Connection,
    scan_id: &str,
    sites: &[SiteRecord],
    project_code_executed: bool,
    stored: Option<CoverageRecord>,
) -> Result<CoverageRecord> {
    let had_final_coverage = stored.is_some();
    let mut coverage = stored.unwrap_or_else(|| CoverageRecord {
        reasons: vec!["final worker coverage unavailable".to_owned()],
        ..CoverageRecord::default()
    });
    coverage.dependency_sites = sites.len() as u64;
    coverage.resolved = 0;
    coverage.candidates = 0;
    coverage.external = 0;
    coverage.unresolved = 0;
    for site in sites {
        match site.resolution_status.as_str() {
            "resolved" => coverage.resolved += 1,
            "candidates" => coverage.candidates += 1,
            "external" => coverage.external += 1,
            "unresolved" => coverage.unresolved += 1,
            _ => {}
        }
    }
    let (profiles, files, skipped): (i64, i64, i64) = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM profiles WHERE scan_id=?1),
            (SELECT COUNT(*) FROM file_coverage WHERE scan_id=?1),
            (SELECT COALESCE(SUM(CASE WHEN skipped THEN 1 ELSE 0 END), 0)
               FROM file_coverage WHERE scan_id=?1)",
        [scan_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    coverage.profiles = profiles as u64;
    coverage.files_discovered = files as u64;
    coverage.files_skipped = skipped as u64;
    coverage.files_analyzed = (files - skipped) as u64;
    coverage.project_code_executed |= project_code_executed;
    if !had_final_coverage {
        coverage.completeness.clear();
    }
    Ok(coverage)
}

pub(crate) fn merge_coverage(mut left: Value, right: Value) -> Value {
    const COUNTERS: &[&str] = &[
        "profiles",
        "files_discovered",
        "files_analyzed",
        "files_skipped",
        "dependency_sites",
        "resolved",
        "candidates",
        "external",
        "unresolved",
        "unsupported_syntax",
    ];
    if !left.is_object() {
        left = json!({});
    }
    for field in COUNTERS {
        let total = left.get(*field).and_then(Value::as_u64).unwrap_or(0)
            + right.get(*field).and_then(Value::as_u64).unwrap_or(0);
        left[*field] = json!(total);
    }
    left["project_code_executed"] = json!(
        left.get("project_code_executed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || right
                .get("project_code_executed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
    );
    let mut completeness = left
        .get("completeness")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let right_completeness = right
        .get("completeness")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // Aggregate completeness is a guarantee about the entire scan. A level
    // is therefore retained only when every contributing worker reported it.
    completeness.retain(|level| right_completeness.contains(level));
    completeness.sort_by_key(Value::to_string);
    completeness.dedup();
    left["completeness"] = Value::Array(completeness);
    let mut reasons = left
        .get("reasons")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    reasons.extend(
        right
            .get("reasons")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
    reasons.sort_by_key(Value::to_string);
    reasons.dedup();
    left["reasons"] = Value::Array(reasons);
    left
}
