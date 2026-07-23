use std::{collections::BTreeSet, path::Path};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    AdapterLogRecord, Store, ensure_scan_staging, ingest_event_in_transaction, required_str,
};

const MAX_SCOPE_VALUES: usize = 100_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncrementalReplacementScope {
    pub paths: Vec<String>,
    pub package_locators: Vec<String>,
    pub profile_ids: Vec<String>,
    pub replanned_profile_ids: Vec<String>,
    pub artifact_node_ids: Vec<String>,
    pub adapters: Vec<String>,
}

impl IncrementalReplacementScope {
    pub fn new(
        paths: impl IntoIterator<Item = String>,
        package_locators: impl IntoIterator<Item = String>,
        profile_ids: impl IntoIterator<Item = String>,
        replanned_profile_ids: impl IntoIterator<Item = String>,
        artifact_node_ids: impl IntoIterator<Item = String>,
        adapters: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let scope = Self {
            paths: normalize_values("path", paths, true)?,
            package_locators: normalize_values("package locator", package_locators, false)?,
            profile_ids: normalize_values("profile ID", profile_ids, false)?,
            replanned_profile_ids: normalize_values(
                "replanned profile ID",
                replanned_profile_ids,
                false,
            )?,
            artifact_node_ids: normalize_values("artifact node ID", artifact_node_ids, false)?,
            adapters: normalize_values("adapter", adapters, false)?,
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<()> {
        if self.paths.is_empty()
            && self.package_locators.is_empty()
            && self.profile_ids.is_empty()
            && self.artifact_node_ids.is_empty()
        {
            bail!("incremental replacement scope must invalidate graph ownership");
        }
        validate_normalized("path", &self.paths, true)?;
        validate_normalized("package locator", &self.package_locators, false)?;
        validate_normalized("profile ID", &self.profile_ids, false)?;
        validate_normalized("replanned profile ID", &self.replanned_profile_ids, false)?;
        if self
            .replanned_profile_ids
            .iter()
            .any(|id| self.profile_ids.binary_search(id).is_err())
        {
            bail!("every replanned profile must also be an affected profile");
        }
        validate_normalized("artifact node ID", &self.artifact_node_ids, false)?;
        validate_normalized("adapter", &self.adapters, false)?;
        Ok(())
    }
}

impl Store {
    pub fn start_incremental_scan_with_revision(
        &mut self,
        scan_id: &str,
        root: &Path,
        strict: bool,
        base_snapshot_id: &str,
        source_revision: Option<&str>,
    ) -> Result<()> {
        if source_revision.is_some_and(|revision| revision.trim().is_empty()) {
            bail!("source revision must not be empty");
        }
        let base = self
            .completed_snapshot(base_snapshot_id)?
            .with_context(|| {
                format!("incremental base snapshot {base_snapshot_id} was not found")
            })?;
        if base.source_kind != "scan" {
            bail!("incremental replacement requires a completed scan snapshot base");
        }
        if self.current_snapshot_id()?.as_deref() != Some(base_snapshot_id) {
            bail!("incremental base snapshot is not the current completed snapshot");
        }
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO scans(
                id, root, status, strict, started_at, protocol_version,
                parent_snapshot_id, source_revision
             ) VALUES (?1, ?2, 'staging', ?3, ?4, '1.0', ?5, ?6)",
            params![
                scan_id,
                root.to_string_lossy(),
                strict,
                Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                base_snapshot_id,
                source_revision,
            ],
        )?;
        tx.commit()?;
        self.clone_completed_scan_into_staging(base_snapshot_id, scan_id)
    }

    pub fn replace_incremental_graph(
        &mut self,
        scan_id: &str,
        base_snapshot_id: &str,
        scope: &IncrementalReplacementScope,
        replacement_events: &[Value],
        adapter_logs: &[AdapterLogRecord],
    ) -> Result<()> {
        scope.validate()?;
        if replacement_events.is_empty() {
            bail!("incremental replacement must include a complete replacement event batch");
        }
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
        let parent: Option<String> = tx.query_row(
            "SELECT parent_snapshot_id FROM scans WHERE id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        if parent.as_deref() != Some(base_snapshot_id) {
            bail!("incremental scan parent does not match its replacement base");
        }
        let current: Option<String> = tx
            .query_row(
                "SELECT snapshot_id FROM current_completed_snapshot WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if current.as_deref() != Some(base_snapshot_id) {
            bail!("incremental replacement base changed before the transaction started");
        }

        let ownership = load_owned_records(&tx, scan_id, scope)?;
        delete_owned_records(&tx, scan_id, scope, &ownership)?;
        let mut completed_events = 0_usize;
        for event in replacement_events {
            if required_str(event, "scan_id")? != scan_id {
                bail!("incremental replacement event targets another scan");
            }
            let event_type = required_str(event, "event")?;
            if event_type == "scan_completed" {
                completed_events += 1;
            }
            ensure_event_is_scoped(&tx, scan_id, scope, event)?;
            ingest_event_in_transaction(&tx, event)?;
        }
        if completed_events != 1 {
            bail!("incremental replacement requires exactly one scan_completed event");
        }
        for log in adapter_logs {
            if scope.adapters.binary_search(&log.adapter).is_err() {
                bail!("incremental adapter log is outside the replacement scope");
            }
            tx.execute(
                "INSERT INTO adapter_logs(scan_id, adapter, stderr, truncated)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(scan_id, adapter) DO UPDATE SET
                    stderr=excluded.stderr, truncated=excluded.truncated",
                params![scan_id, log.adapter, log.stderr, log.truncated],
            )?;
        }
        let coverage_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM coverage WHERE scan_id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        if coverage_count != 1 {
            bail!("incremental replacement did not produce aggregate coverage");
        }
        tx.execute(
            "UPDATE scans SET mutation_count=mutation_count+1 WHERE id=?1",
            [scan_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[derive(Default)]
struct OwnedRecords {
    nodes: BTreeSet<String>,
    sites: BTreeSet<String>,
    edges: BTreeSet<String>,
    diagnostics: BTreeSet<String>,
}

fn load_owned_records(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
) -> Result<OwnedRecords> {
    let mut owned = OwnedRecords::default();
    let mut nodes = tx.prepare(
        "SELECT id, kind, locator, properties_json FROM nodes WHERE scan_id=?1 ORDER BY id",
    )?;
    for row in nodes.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })? {
        let (id, kind, locator, raw) = row?;
        let properties: Value = serde_json::from_str(&raw)?;
        if scope.artifact_node_ids.binary_search(&id).is_ok()
            || (kind == "package_instance"
                && scope.package_locators.binary_search(&locator).is_ok())
            || scope.paths.binary_search(&locator).is_ok()
            || has_named_value(
                &properties,
                &[
                    "path",
                    "source_path",
                    "manifest_path",
                    "relative_path",
                    "logical_path",
                ],
                &scope.paths,
            )
            || has_named_value(&properties, &["package_locator"], &scope.package_locators)
            || has_named_value(&properties, &["profile_id"], &scope.replanned_profile_ids)
        {
            owned.nodes.insert(id);
        }
    }

    let mut evidence = tx.prepare(
        "SELECT owner_type, owner_id, path FROM evidence WHERE scan_id=?1
         ORDER BY owner_type, owner_id, ordinal",
    )?;
    for row in evidence.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (owner_type, owner_id, path) = row?;
        if scope.paths.binary_search(&path).is_ok() {
            match owner_type.as_str() {
                "node" => {
                    owned.nodes.insert(owner_id);
                }
                "site" => {
                    owned.sites.insert(owner_id);
                }
                "edge" => {
                    owned.edges.insert(owner_id);
                }
                "diagnostic" => {
                    owned.diagnostics.insert(owner_id);
                }
                _ => {}
            }
        }
    }

    let mut sites =
        tx.prepare("SELECT id, source, profile_id FROM sites WHERE scan_id=?1 ORDER BY id")?;
    for row in sites.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (id, source, profile_id) = row?;
        if owned.nodes.contains(&source)
            || scope
                .replanned_profile_ids
                .binary_search(&profile_id)
                .is_ok()
        {
            owned.sites.insert(id);
        }
    }

    let mut edges = tx.prepare(
        "SELECT id, site_id, source, target, profile_id FROM edges WHERE scan_id=?1 ORDER BY id",
    )?;
    for row in edges.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })? {
        let (id, site_id, source, target, profile_id) = row?;
        if owned.nodes.contains(&source)
            || owned.nodes.contains(&target)
            || site_id.is_some_and(|site_id| owned.sites.contains(&site_id))
            || scope
                .replanned_profile_ids
                .binary_search(&profile_id)
                .is_ok()
        {
            owned.edges.insert(id);
        }
    }

    let mut diagnostics =
        tx.prepare("SELECT id, path, raw_json FROM diagnostics WHERE scan_id=?1 ORDER BY id")?;
    for row in diagnostics.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (id, path, raw) = row?;
        let diagnostic: Value = serde_json::from_str(&raw)?;
        if path.is_some_and(|path| scope.paths.binary_search(&path).is_ok())
            || has_named_value(&diagnostic, &["profile_id"], &scope.replanned_profile_ids)
        {
            owned.diagnostics.insert(id);
        }
    }
    Ok(owned)
}

fn delete_owned_records(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    owned: &OwnedRecords,
) -> Result<()> {
    for (owner_type, ids) in [
        ("node", &owned.nodes),
        ("edge", &owned.edges),
        ("site", &owned.sites),
        ("diagnostic", &owned.diagnostics),
    ] {
        for id in ids {
            tx.execute(
                "DELETE FROM evidence WHERE scan_id=?1 AND owner_type=?2 AND owner_id=?3",
                params![scan_id, owner_type, id],
            )?;
        }
    }
    delete_ids(tx, "edges", scan_id, &owned.edges)?;
    delete_ids(tx, "sites", scan_id, &owned.sites)?;
    delete_ids(tx, "diagnostics", scan_id, &owned.diagnostics)?;
    delete_ids(tx, "nodes", scan_id, &owned.nodes)?;
    for path in &scope.paths {
        tx.execute(
            "DELETE FROM file_coverage WHERE scan_id=?1 AND path=?2",
            params![scan_id, path],
        )?;
    }
    for profile_id in &scope.profile_ids {
        tx.execute(
            "DELETE FROM profile_coverage WHERE scan_id=?1 AND profile_id=?2",
            params![scan_id, profile_id],
        )?;
    }
    for profile_id in &scope.replanned_profile_ids {
        tx.execute(
            "DELETE FROM profiles WHERE scan_id=?1 AND id=?2",
            params![scan_id, profile_id],
        )?;
    }
    for adapter in &scope.adapters {
        tx.execute(
            "DELETE FROM adapter_logs WHERE scan_id=?1 AND adapter=?2",
            params![scan_id, adapter],
        )?;
    }
    tx.execute("DELETE FROM coverage WHERE scan_id=?1", [scan_id])?;
    Ok(())
}

fn delete_ids(
    tx: &Transaction<'_>,
    table: &str,
    scan_id: &str,
    ids: &BTreeSet<String>,
) -> Result<()> {
    let sql = match table {
        "nodes" => "DELETE FROM nodes WHERE scan_id=?1 AND id=?2",
        "sites" => "DELETE FROM sites WHERE scan_id=?1 AND id=?2",
        "edges" => "DELETE FROM edges WHERE scan_id=?1 AND id=?2",
        "diagnostics" => "DELETE FROM diagnostics WHERE scan_id=?1 AND id=?2",
        _ => unreachable!("incremental deletion uses fixed table names"),
    };
    for id in ids {
        tx.execute(sql, params![scan_id, id])?;
    }
    Ok(())
}

fn ensure_event_is_scoped(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    event: &Value,
) -> Result<()> {
    let event_type = required_str(event, "event")?;
    let adapter = event
        .get("adapter")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if !matches!(event_type, "scan_started" | "scan_completed")
        && adapter != "core"
        && scope.adapters.binary_search(&adapter.to_owned()).is_err()
    {
        bail!("incremental replacement event adapter is outside the replacement scope");
    }
    match event_type {
        "profile_declared" => {
            let profile = event
                .get("profile")
                .context("profile_declared is missing profile")?;
            let id = required_str(profile, "id")?;
            if scope
                .replanned_profile_ids
                .binary_search(&id.to_owned())
                .is_err()
            {
                let existing = ensure_existing_value_is_unchanged(
                    tx, "profiles", "json", scan_id, id, profile,
                )?;
                if !existing {
                    bail!("incremental replacement introduced an out-of-scope profile");
                }
            }
        }
        "node_upsert" => {
            let node = event.get("node").context("node_upsert is missing node")?;
            let existing = ensure_existing_value_is_unchanged(
                tx,
                "nodes",
                "raw_json",
                scan_id,
                required_str(node, "id")?,
                node,
            )?;
            if !existing && !node_is_scoped(scope, node)? {
                bail!("incremental replacement introduced an out-of-scope node");
            }
        }
        "dependency_site" => {
            let site = event
                .get("site")
                .context("dependency_site is missing site")?;
            let existing = ensure_existing_value_is_unchanged(
                tx,
                "sites",
                "raw_json",
                scan_id,
                required_str(site, "id")?,
                site,
            )?;
            if !existing && !site_is_scoped(tx, scan_id, scope, site)? {
                bail!("incremental replacement introduced an out-of-scope dependency site");
            }
        }
        "edge_upsert" => {
            let edge = event.get("edge").context("edge_upsert is missing edge")?;
            let existing = ensure_existing_value_is_unchanged(
                tx,
                "edges",
                "raw_json",
                scan_id,
                required_str(edge, "id")?,
                edge,
            )?;
            if !existing && !edge_is_scoped(tx, scan_id, scope, edge)? {
                bail!("incremental replacement introduced an out-of-scope edge");
            }
        }
        "diagnostic" => {
            let diagnostic = event
                .get("diagnostic")
                .context("diagnostic is missing payload")?;
            let existing = diagnostic
                .get("id")
                .and_then(Value::as_str)
                .map(|id| {
                    ensure_existing_value_is_unchanged(
                        tx,
                        "diagnostics",
                        "raw_json",
                        scan_id,
                        id,
                        diagnostic,
                    )
                })
                .transpose()?
                .unwrap_or(false);
            if !existing && !diagnostic_is_scoped(scope, diagnostic) {
                bail!("incremental replacement introduced an out-of-scope diagnostic");
            }
        }
        "file_completed" => {
            let path = required_str(event, "path")?;
            if scope.paths.binary_search(&path.to_owned()).is_err() {
                bail!("incremental file coverage is outside the replacement scope");
            }
        }
        "profile_completed" => {
            let profile_id = required_str(event, "profile_id")?;
            if scope
                .profile_ids
                .binary_search(&profile_id.to_owned())
                .is_err()
            {
                bail!("incremental profile coverage is outside the replacement scope");
            }
        }
        "scan_started" | "scan_completed" => {}
        other => bail!("unknown incremental replacement event {other}"),
    }
    Ok(())
}

fn ensure_existing_value_is_unchanged(
    tx: &Transaction<'_>,
    table: &str,
    column: &str,
    scan_id: &str,
    id: &str,
    replacement: &Value,
) -> Result<bool> {
    let sql = match (table, column) {
        ("profiles", "json") => "SELECT json FROM profiles WHERE scan_id=?1 AND id=?2",
        ("nodes", "raw_json") => "SELECT raw_json FROM nodes WHERE scan_id=?1 AND id=?2",
        ("sites", "raw_json") => "SELECT raw_json FROM sites WHERE scan_id=?1 AND id=?2",
        ("edges", "raw_json") => "SELECT raw_json FROM edges WHERE scan_id=?1 AND id=?2",
        ("diagnostics", "raw_json") => {
            "SELECT raw_json FROM diagnostics WHERE scan_id=?1 AND id=?2"
        }
        _ => unreachable!("incremental upsert checks use fixed table and column names"),
    };
    let existing = tx
        .query_row(sql, params![scan_id, id], |row| row.get::<_, String>(0))
        .optional()?;
    if let Some(existing) = existing {
        let existing: Value = serde_json::from_str(&existing)?;
        if existing != *replacement {
            bail!("incremental replacement attempted to mutate an out-of-scope record");
        }
        return Ok(true);
    }
    Ok(false)
}

fn node_is_scoped(scope: &IncrementalReplacementScope, node: &Value) -> Result<bool> {
    let id = required_str(node, "id")?;
    let kind = required_str(node, "kind")?;
    let locator = required_str(node, "locator")?;
    let properties = node.get("properties").unwrap_or(&Value::Null);
    Ok(scope
        .artifact_node_ids
        .binary_search(&id.to_owned())
        .is_ok()
        || (kind == "package_instance"
            && scope
                .package_locators
                .binary_search(&locator.to_owned())
                .is_ok())
        || has_named_value(
            properties,
            &[
                "path",
                "source_path",
                "manifest_path",
                "relative_path",
                "logical_path",
            ],
            &scope.paths,
        )
        || has_named_value(properties, &["package_locator"], &scope.package_locators)
        || has_named_value(properties, &["profile_id"], &scope.replanned_profile_ids))
}

fn site_is_scoped(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    site: &Value,
) -> Result<bool> {
    let profile_id = required_str(site, "profile_id")?;
    if scope
        .replanned_profile_ids
        .binary_search(&profile_id.to_owned())
        .is_ok()
    {
        return Ok(true);
    }
    stored_node_is_scoped(tx, scan_id, scope, required_str(site, "source")?)
}

fn edge_is_scoped(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    edge: &Value,
) -> Result<bool> {
    let profile_id = required_str(edge, "profile_id")?;
    if scope
        .replanned_profile_ids
        .binary_search(&profile_id.to_owned())
        .is_ok()
        || stored_node_is_scoped(tx, scan_id, scope, required_str(edge, "source")?)?
        || stored_node_is_scoped(tx, scan_id, scope, required_str(edge, "target")?)?
    {
        return Ok(true);
    }
    let Some(site_id) = edge.get("site_id").and_then(Value::as_str) else {
        return Ok(false);
    };
    let raw = tx
        .query_row(
            "SELECT raw_json FROM sites WHERE scan_id=?1 AND id=?2",
            params![scan_id, site_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    raw.map(|raw| serde_json::from_str::<Value>(&raw))
        .transpose()?
        .map(|site| site_is_scoped(tx, scan_id, scope, &site))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn stored_node_is_scoped(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    node_id: &str,
) -> Result<bool> {
    let raw = tx
        .query_row(
            "SELECT raw_json FROM nodes WHERE scan_id=?1 AND id=?2",
            params![scan_id, node_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    raw.map(|raw| serde_json::from_str::<Value>(&raw))
        .transpose()?
        .map(|node| node_is_scoped(scope, &node))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn diagnostic_is_scoped(scope: &IncrementalReplacementScope, diagnostic: &Value) -> bool {
    diagnostic
        .get("path")
        .and_then(Value::as_str)
        .is_some_and(|path| scope.paths.binary_search(&path.to_owned()).is_ok())
        || has_named_value(diagnostic, &["profile_id"], &scope.replanned_profile_ids)
}

fn has_named_value(value: &Value, keys: &[&str], candidates: &[String]) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (keys.contains(&key.as_str())
                && value
                    .as_str()
                    .is_some_and(|value| candidates.binary_search(&value.to_owned()).is_ok()))
                || has_named_value(value, keys, candidates)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| has_named_value(value, keys, candidates)),
        _ => false,
    }
}

fn normalize_values(
    name: &str,
    values: impl IntoIterator<Item = String>,
    paths: bool,
) -> Result<Vec<String>> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    if values.len() > MAX_SCOPE_VALUES {
        bail!("incremental {name} scope exceeds {MAX_SCOPE_VALUES} values");
    }
    for value in &mut values {
        *value = if paths {
            normalize_path(value)?
        } else {
            validate_value(name, value)?;
            value.clone()
        };
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn validate_normalized(name: &str, values: &[String], paths: bool) -> Result<()> {
    if values.len() > MAX_SCOPE_VALUES || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("incremental {name} scope is not canonical");
    }
    for value in values {
        if paths {
            if normalize_path(value)? != *value {
                bail!("incremental path scope is not canonical");
            }
        } else {
            validate_value(name, value)?;
        }
    }
    Ok(())
}

fn validate_value(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 2_048 || value.chars().any(char::is_control) {
        bail!("incremental {name} must be a bounded printable value");
    }
    Ok(())
}

fn normalize_path(value: &str) -> Result<String> {
    let normalized = value.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.ends_with('/')
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || normalized.contains(':')
        || normalized.chars().any(char::is_control)
        || normalized.len() > 4_096
    {
        bail!("incremental path must be a canonical repository-relative path");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn common(scan_id: &str, event: &str, seq: u64) -> Value {
        json!({
            "event":event,"protocol_version":"1.0","scan_id":scan_id,
            "adapter":"web","adapter_version":"1.0.0","seq":seq
        })
    }

    fn graph_events(scan_id: &str, renamed: bool) -> Vec<Value> {
        let a_path = if renamed {
            "a/src/renamed.ts"
        } else {
            "a/src/index.ts"
        };
        let a_target = if renamed {
            "file:a:new-target"
        } else {
            "file:a:target"
        };
        let mut seq = 1_u64;
        let mut events = Vec::new();
        for (profile_id, package, path, source, target) in [
            ("web:a", "package:a", a_path, "file:a:source", a_target),
            (
                "web:b",
                "package:b",
                "b/src/index.ts",
                "file:b:source",
                "file:b:target",
            ),
        ] {
            let revision = if profile_id == "web:a" && renamed {
                2
            } else {
                1
            };
            let mut profile = common(scan_id, "profile_declared", seq);
            seq += 1;
            profile["profile"] = json!({
                "id":profile_id,"language":"typescript","features":[],"environment":{},
                "properties":{"package_locator":package}
            });
            events.push(profile);
            for (id, node_path) in [(source, path), (target, path)] {
                let mut node = common(scan_id, "node_upsert", seq);
                seq += 1;
                node["node"] = json!({
                    "id":id,"kind":"file","locator":node_path,"display_name":node_path,
                    "properties":{"path":node_path,"package_locator":package,
                        "profile_id":profile_id,"revision":revision}
                });
                events.push(node);
            }
            let mut site = common(scan_id, "dependency_site", seq);
            seq += 1;
            site["site"] = json!({
                "id":format!("site:{profile_id}"),"source":source,"kind":"import",
                "specifier":"./target","profile_id":profile_id,"resolution_status":"resolved",
                "precision":"exact","condition":{"op":"all","conditions":[]},
                "target_ids":[target],"evidence":[{"kind":"source","extractor":"fixture",
                    "extractor_version":"1.0.0","path":path,"start_line":1,"start_column":1,
                    "end_line":1,"end_column":2,"properties":{}}]
            });
            events.push(site);
            let mut edge = common(scan_id, "edge_upsert", seq);
            seq += 1;
            edge["edge"] = json!({
                "id":format!("edge:{profile_id}"),"site_id":format!("site:{profile_id}"),
                "source":source,"target":target,"kind":"imports","phase":"source",
                "environment":"any","profile_id":profile_id,"resolution_status":"resolved",
                "precision":"exact","condition":{"op":"all","conditions":[]},"generated":false,
                "evidence":[{"kind":"source","extractor":"fixture","extractor_version":"1.0.0",
                    "path":path,"start_line":1,"start_column":1,"end_line":1,"end_column":2,
                    "properties":{}}]
            });
            events.push(edge);
            let mut file = common(scan_id, "file_completed", seq);
            seq += 1;
            file["path"] = json!(path);
            file["discovered_sites"] = json!(1);
            file["emitted_sites"] = json!(1);
            file["skipped_sites"] = json!(0);
            file["skipped"] = json!(false);
            events.push(file);
            let coverage = json!({
                "profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,
                "dependency_sites":1,"resolved":1,"candidates":0,"external":0,"unresolved":0,
                "unsupported_syntax":0,"project_code_executed":false,
                "completeness":["syntax-complete"],"reasons":[]
            });
            let mut completed = common(scan_id, "profile_completed", seq);
            seq += 1;
            completed["profile_id"] = json!(profile_id);
            completed["coverage"] = coverage;
            events.push(completed);
        }
        let mut completed = common(scan_id, "scan_completed", seq);
        completed["coverage"] = json!({
            "profiles":2,"files_discovered":2,"files_analyzed":2,"files_skipped":0,
            "dependency_sites":2,"resolved":2,"candidates":0,"external":0,"unresolved":0,
            "unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        events.push(completed);
        events
    }

    fn complete(store: &mut Store, scan_id: &str, events: &[Value]) -> String {
        store
            .start_scan(scan_id, Path::new("/fixture"), false)
            .unwrap();
        let refs = events.iter().collect::<Vec<_>>();
        store.ingest_events(&refs).unwrap();
        store.validate_scan(scan_id).unwrap();
        store.finish_scan(scan_id, "completed", None, true).unwrap();
        store
            .snapshot_id_for_source("scan", scan_id)
            .unwrap()
            .unwrap()
    }

    fn replacement_events(scan_id: &str) -> Vec<Value> {
        graph_events(scan_id, true)
            .into_iter()
            .filter(|event| {
                event["event"] == "scan_completed"
                    || event["profile"]["id"] == "web:a"
                    || event["node"]["properties"]["profile_id"] == "web:a"
                    || event["site"]["profile_id"] == "web:a"
                    || event["edge"]["profile_id"] == "web:a"
                    || event["profile_id"] == "web:a"
                    || event["path"] == "a/src/renamed.ts"
            })
            .collect()
    }

    fn scope() -> IncrementalReplacementScope {
        IncrementalReplacementScope::new(
            ["a/src/index.ts".to_owned(), "a/src/renamed.ts".to_owned()],
            ["package:a".to_owned()],
            ["web:a".to_owned()],
            std::iter::empty(),
            std::iter::empty(),
            ["web".to_owned()],
        )
        .unwrap()
    }

    #[test]
    fn transactional_replacement_matches_a_full_scan_and_removes_renamed_ownership() {
        let mut incremental = Store::open_in_memory().unwrap();
        let base_id = complete(&mut incremental, "base", &graph_events("base", false));
        incremental
            .start_incremental_scan_with_revision(
                "incremental",
                Path::new("/fixture"),
                false,
                &base_id,
                Some("revision-2"),
            )
            .unwrap();
        incremental
            .replace_incremental_graph(
                "incremental",
                &base_id,
                &scope(),
                &replacement_events("incremental"),
                &[AdapterLogRecord {
                    adapter: "web".to_owned(),
                    stderr: String::new(),
                    truncated: false,
                }],
            )
            .unwrap();
        incremental.validate_scan("incremental").unwrap();
        incremental
            .finish_scan("incremental", "completed", None, true)
            .unwrap();

        let mut full = Store::open_in_memory().unwrap();
        complete(&mut full, "full", &graph_events("full", true));
        let incremental_graph = incremental.load_snapshot("incremental").unwrap();
        let full_graph = full.load_snapshot("full").unwrap();
        assert_eq!(incremental_graph.profiles, full_graph.profiles);
        assert_eq!(incremental_graph.nodes, full_graph.nodes);
        assert_eq!(incremental_graph.sites, full_graph.sites);
        assert_eq!(incremental_graph.edges, full_graph.edges);
        assert_eq!(incremental_graph.evidence, full_graph.evidence);
        assert_eq!(incremental_graph.file_coverage, full_graph.file_coverage);
        assert_eq!(incremental_graph.coverage, full_graph.coverage);
        assert!(
            incremental_graph
                .nodes
                .iter()
                .all(|node| node.locator != "a/src/index.ts")
        );
    }

    #[test]
    fn failed_replacement_rolls_back_and_keeps_the_completed_snapshot_current() {
        let mut store = Store::open_in_memory().unwrap();
        let base_id = complete(&mut store, "base", &graph_events("base", false));
        let base = store.load_completed_snapshot(&base_id).unwrap();
        store
            .start_incremental_scan_with_revision(
                "failed",
                Path::new("/fixture"),
                false,
                &base_id,
                None,
            )
            .unwrap();
        let mut events = replacement_events("failed");
        events.insert(
            1,
            json!({"event":"node_upsert","protocol_version":"1.0","scan_id":"failed",
                "adapter":"web","adapter_version":"1.0.0","seq":999,"node":{
                    "id":"file:rogue","kind":"file","locator":"rogue/src/index.ts",
                    "display_name":"rogue/src/index.ts","properties":{
                        "path":"rogue/src/index.ts","package_locator":"package:rogue",
                        "profile_id":"web:rogue"}}}),
        );
        assert!(
            store
                .replace_incremental_graph("failed", &base_id, &scope(), &events, &[])
                .is_err()
        );
        let staging = store.load_snapshot("failed").unwrap();
        assert_eq!(staging.nodes, base.nodes);
        assert_eq!(staging.sites, base.sites);
        assert_eq!(staging.edges, base.edges);
        store
            .finish_scan(
                "failed",
                "failed",
                Some("incremental replacement failed"),
                false,
            )
            .unwrap();
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(base_id.as_str())
        );
        assert_eq!(store.load_completed_snapshot(&base_id).unwrap(), base);
    }

    #[test]
    fn idless_out_of_scope_diagnostic_is_rejected_and_rolled_back() {
        let mut store = Store::open_in_memory().unwrap();
        let base_id = complete(&mut store, "base", &graph_events("base", false));
        let base = store.load_completed_snapshot(&base_id).unwrap();
        store
            .start_incremental_scan_with_revision(
                "failed-diagnostic",
                Path::new("/fixture"),
                false,
                &base_id,
                None,
            )
            .unwrap();
        let mut events = replacement_events("failed-diagnostic");
        events.insert(
            1,
            json!({"event":"diagnostic","protocol_version":"1.0",
                "scan_id":"failed-diagnostic","adapter":"web","adapter_version":"1.0.0",
                "seq":999,"diagnostic":{"severity":"warning","code":"ROGUE",
                    "message":"outside replacement scope","path":"b/src/index.ts",
                    "recoverable":true,"properties":{}}}),
        );
        assert!(
            store
                .replace_incremental_graph("failed-diagnostic", &base_id, &scope(), &events, &[],)
                .is_err()
        );
        let staging = store.load_snapshot("failed-diagnostic").unwrap();
        assert_eq!(staging.nodes, base.nodes);
        assert_eq!(staging.diagnostics, base.diagnostics);
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(base_id.as_str())
        );
    }
}
