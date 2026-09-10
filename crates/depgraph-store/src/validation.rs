//! Graph contract checks used before completing a scan.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use rusqlite::Connection;

use crate::read::{
    EdgeValidationRecord, SiteValidationRecord, ValidationTargetKind, visit_site_validation_groups,
};

// Each arm uses a covering endpoint index. Only invalid edge rowids enter
// the UNION, which counts an edge once even when both endpoints are missing.
const MISSING_NODE_EDGES_SQL: &str = "
SELECT COUNT(*) FROM (
    SELECT edge.rowid FROM edges AS edge WHERE edge.scan_id=?1
       AND NOT EXISTS(SELECT 1 FROM nodes AS node
                       WHERE node.scan_id=edge.scan_id AND node.id=edge.source)
    UNION
    SELECT edge.rowid FROM edges AS edge WHERE edge.scan_id=?1
       AND NOT EXISTS(SELECT 1 FROM nodes AS node
                       WHERE node.scan_id=edge.scan_id AND node.id=edge.target)
)";

pub(crate) struct ScanValidationCounts {
    pub(crate) sites: i64,
    pub(crate) resolved: i64,
    pub(crate) candidates: i64,
    pub(crate) external: i64,
    pub(crate) unresolved: i64,
    pub(crate) sites_by_profile: BTreeMap<String, [u64; 5]>,
}

pub(crate) fn validate_scan_graph(
    connection: &Connection,
    scan_id: &str,
) -> Result<ScanValidationCounts> {
    let missing_nodes: i64 = crate::profiling::run("store-validate-endpoints", || {
        Ok(connection.query_row(MISSING_NODE_EDGES_SQL, [scan_id], |row| row.get(0))?)
    })?;
    if missing_nodes > 0 {
        bail!("scan {scan_id} has {missing_nodes} edges with missing endpoint nodes");
    }
    let (site_count, resolved, candidates, external, unresolved): (i64, i64, i64, i64, i64) =
        connection.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN resolution_status='resolved' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN resolution_status='candidates' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN resolution_status='external' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN resolution_status='unresolved' THEN 1 ELSE 0 END), 0)
             FROM sites WHERE scan_id = ?1",
            [scan_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
    if site_count != resolved + candidates + external + unresolved {
        bail!("coverage invariant failed for scan {scan_id}");
    }

    let mut sites_by_profile = BTreeMap::<String, [u64; 5]>::new();
    let mut invalid_sentinels = 0_u64;
    let mut first_site_error = None;
    crate::profiling::run("store-validate-sites", || {
        visit_site_validation_groups(connection, scan_id, |site, site_edges| {
            let counts = sites_by_profile.entry(site.profile_id.clone()).or_default();
            counts[0] += 1;
            let status_index = match site.resolution_status.as_str() {
                "resolved" => 1,
                "candidates" => 2,
                "external" => 3,
                "unresolved" => 4,
                status => bail!("site {} has unknown resolution status {status}", site.id),
            };
            counts[status_index] += 1;
            invalid_sentinels += site_edges
                .iter()
                .filter(|edge| match site.resolution_status.as_str() {
                    "resolved" => edge.target_kind.is_some(),
                    "external" => edge.target_kind != Some(ValidationTargetKind::ExternalSystem),
                    "unresolved" => edge.target_kind != Some(ValidationTargetKind::UnknownTarget),
                    _ => false,
                })
                .count() as u64;
            // The old path decoded every row and checked sentinel counts before
            // per-site contracts. Keep that precedence without retaining rows.
            if first_site_error.is_none() {
                first_site_error = validate_site_contract(&site, site_edges).err();
            }
            Ok(())
        })
    })?;
    if invalid_sentinels > 0 {
        bail!("scan {scan_id} has {invalid_sentinels} invalid resolution target classifications");
    }
    if let Some(error) = first_site_error {
        return Err(error);
    }
    Ok(ScanValidationCounts {
        sites: site_count,
        resolved,
        candidates,
        external,
        unresolved,
        sites_by_profile,
    })
}

fn validate_site_contract(
    site: &SiteValidationRecord,
    site_edges: &[EdgeValidationRecord],
) -> Result<()> {
    let expected = site
        .target_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if expected.len() != site.target_ids.len() {
        bail!("site {} contains duplicate target IDs", site.id);
    }
    match site.resolution_status.as_str() {
        "resolved" | "external" | "unresolved" if expected.len() == 1 && site_edges.len() == 1 => {}
        "candidates" if !expected.is_empty() && site_edges.len() == expected.len() => {}
        "resolved" | "candidates" | "external" | "unresolved" => bail!(
            "site {} violates {} cardinality: {} targets, {} edges",
            site.id,
            site.resolution_status,
            expected.len(),
            site_edges.len()
        ),
        status => bail!("site {} has unknown resolution status {status}", site.id),
    }
    let observed = site_edges
        .iter()
        .map(|edge| edge.target.as_str())
        .collect::<BTreeSet<_>>();
    if expected != observed || site_edges.len() != expected.len() {
        bail!("site {} target IDs do not match its edge targets", site.id);
    }
    for edge in site_edges {
        if edge.source != site.source
            || edge.profile_id != site.profile_id
            || edge.resolution_status != site.resolution_status
            || edge.precision != site.precision
        {
            bail!(
                "site {} and edge {} disagree on contract fields",
                site.id,
                edge.id
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use rusqlite::params;
    use serde_json::Value;
    use std::path::Path;

    const SCAN: &str = "validation-fixture";
    const SOURCE: &str = "file:sha256:source";
    const TARGET: &str = "file:sha256:target";
    const SITE: &str = "site:sha256:import";
    const LEGACY_ENDPOINTS: &str = "
        SELECT COUNT(*) FROM edges e
        LEFT JOIN nodes src ON src.scan_id=e.scan_id AND src.id=e.source
        LEFT JOIN nodes dst ON dst.scan_id=e.scan_id AND dst.id=e.target
        WHERE e.scan_id=?1 AND (src.id IS NULL OR dst.id IS NULL)";
    const LEGACY_SENTINELS: &str = "
        SELECT COUNT(*) FROM sites s
        JOIN edges e ON e.scan_id=s.scan_id AND e.site_id=s.id
        JOIN nodes n ON n.scan_id=e.scan_id AND n.id=e.target
        WHERE s.scan_id=?1
        AND ((s.resolution_status='resolved' AND n.kind IN ('external_system','unknown_target'))
          OR (s.resolution_status='external' AND n.kind!='external_system')
          OR (s.resolution_status='unresolved' AND n.kind!='unknown_target'))";

    fn fixture() -> Result<Store> {
        let mut store = Store::open_in_memory()?;
        store.start_scan(SCAN, Path::new("/fixture"), false)?;
        let mut events =
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson")
                .lines()
                .map(serde_json::from_str::<Value>)
                .collect::<serde_json::Result<Vec<_>>>()?;
        events.sort_by_key(|event| (event["event"] == "edge_upsert") as u8);
        for mut event in events {
            event["scan_id"] = serde_json::json!(SCAN);
            store.ingest_event(&event)?;
        }
        Ok(store)
    }

    fn copy_edge(
        store: &Store,
        id: &str,
        site: Option<&str>,
        source: &str,
        target: &str,
    ) -> Result<()> {
        store.connection.execute(
            "INSERT INTO edges(scan_id,id,site_id,source,target,kind,phase,environment,
                               profile_id,resolution_status,precision,condition_json,generated,raw_json)
             SELECT scan_id,?1,?2,?3,?4,kind,phase,environment,profile_id,
                    resolution_status,precision,condition_json,generated,raw_json
               FROM edges WHERE scan_id=?5 AND id='edge:sha256:import'",
            params![id,site,source,target,SCAN],
        )?;
        Ok(())
    }

    fn error_text(store: &Store) -> String {
        match validate_scan_graph(&store.connection, SCAN) {
            Ok(_) => panic!("invalid graph passed validation"),
            Err(error) => format!("{error:#}"),
        }
    }

    #[test]
    fn endpoint_queries_cover_indexes_and_count_each_bad_edge_once() -> Result<()> {
        let store = fixture()?;
        let plan = store
            .connection
            .prepare(&format!("EXPLAIN QUERY PLAN {MISSING_NODE_EDGES_SQL}"))?
            .query_map([SCAN], |row| row.get::<_, String>(3))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .join("\n");
        assert!(plan.contains("COVERING INDEX edges_scan_source"), "{plan}");
        assert!(plan.contains("COVERING INDEX edges_scan_target"), "{plan}");
        copy_edge(&store, "bad-source", Some(SITE), "missing", TARGET)?;
        copy_edge(&store, "bad-target", Some(SITE), SOURCE, "missing")?;
        copy_edge(&store, "bad-both", Some(SITE), "missing", "missing")?;
        for query in [LEGACY_ENDPOINTS, MISSING_NODE_EDGES_SQL] {
            let count: i64 = store
                .connection
                .query_row(query, [SCAN], |row| row.get(0))?;
            assert_eq!(count, 3);
        }
        assert!(error_text(&store).contains("3 edges with missing endpoint nodes"));
        // A node with the same ID in another scan must not satisfy the check.
        store.connection.execute(
            "INSERT INTO scans(id,root,status,strict,started_at,protocol_version)
             VALUES('other','/fixture','staging',0,'fixture','1.0')",
            [],
        )?;
        store.connection.execute(
            "INSERT INTO nodes(scan_id,id,kind,locator,display_name,properties_json,raw_json)
             VALUES('other','missing','file','missing','missing','{}','{}')",
            [],
        )?;
        assert!(error_text(&store).contains("3 edges with missing endpoint nodes"));
        Ok(())
    }

    #[test]
    fn streamed_target_classification_matches_the_join_for_every_status() -> Result<()> {
        for status in ["resolved", "candidates", "external", "unresolved"] {
            for kind in ["file", "symbol", "external_system", "unknown_target"] {
                let store = fixture()?;
                store
                    .connection
                    .execute("UPDATE sites SET resolution_status=?1", [status])?;
                store
                    .connection
                    .execute("UPDATE edges SET resolution_status=?1", [status])?;
                store.connection.execute(
                    "UPDATE nodes SET kind=?1 WHERE id=?2",
                    params![kind, TARGET],
                )?;
                let legacy: i64 = store
                    .connection
                    .query_row(LEGACY_SENTINELS, [SCAN], |row| row.get(0))?;
                if legacy == 0 {
                    let counts = validate_scan_graph(&store.connection, SCAN)?;
                    assert_eq!(counts.sites, 1);
                    assert_eq!(counts.sites_by_profile["web:production:server"][0], 1);
                } else {
                    assert_eq!(legacy, 1);
                    assert!(
                        error_text(&store).contains("1 invalid resolution target classifications"),
                        "{status}/{kind}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn streamed_sites_reject_cardinality_targets_and_contract_field_mismatches() -> Result<()> {
        for (sql, expected) in [
            ("UPDATE sites SET target_ids_json='[]'", "cardinality"),
            (
                "UPDATE sites SET target_ids_json='[\"file:sha256:target\",\"file:sha256:target\"]'",
                "duplicate target IDs",
            ),
            (
                "UPDATE sites SET target_ids_json='[\"file:sha256:source\"]'",
                "target IDs do not match",
            ),
            ("DELETE FROM edges", "cardinality"),
            (
                "UPDATE edges SET source='file:sha256:target'",
                "disagree on contract fields",
            ),
            (
                "UPDATE edges SET profile_id='other'",
                "disagree on contract fields",
            ),
            (
                "UPDATE edges SET precision='heuristic'",
                "disagree on contract fields",
            ),
            (
                "UPDATE edges SET resolution_status='candidates'",
                "disagree on contract fields",
            ),
            (
                "UPDATE sites SET resolution_status='unexpected'",
                "coverage invariant",
            ),
            ("UPDATE sites SET target_ids_json='{}'", "invalid type"),
        ] {
            let store = fixture()?;
            store.connection.execute(sql, [])?;
            let error = error_text(&store);
            assert!(error.contains(expected), "{sql}: {error}");
        }
        let store = fixture()?;
        copy_edge(&store, "duplicate-target", Some(SITE), SOURCE, TARGET)?;
        assert!(error_text(&store).contains("cardinality"));
        store.connection.execute(
            "UPDATE sites SET resolution_status='candidates',
             target_ids_json='[\"file:sha256:source\",\"file:sha256:target\"]'",
            [],
        )?;
        store
            .connection
            .execute("UPDATE edges SET resolution_status='candidates'", [])?;
        assert!(error_text(&store).contains("target IDs do not match"));
        store.connection.execute(
            "UPDATE edges SET target=?1 WHERE id='duplicate-target'",
            [SOURCE],
        )?;
        validate_scan_graph(&store.connection, SCAN)?;
        Ok(())
    }

    #[test]
    fn ordered_validation_groups_edges_by_site_and_decodes_unattached_rows() -> Result<()> {
        let store = fixture()?;
        for (site, edge) in [("雪", "a"), ("a", "z")] {
            store.connection.execute(
                "INSERT INTO sites(scan_id,id,source,kind,specifier,profile_id,resolution_status,
                                   precision,condition_json,target_ids_json,reason,raw_json)
                 SELECT scan_id,?1,source,kind,specifier,profile_id,resolution_status,
                        precision,condition_json,target_ids_json,reason,raw_json
                   FROM sites WHERE scan_id=?2 AND id=?3",
                params![site, SCAN, SITE],
            )?;
            copy_edge(&store, edge, Some(site), SOURCE, TARGET)?;
        }
        assert_eq!(validate_scan_graph(&store.connection, SCAN)?.sites, 3);
        for site in [None, Some("0-orphan"), Some("雪-orphan")] {
            let store = fixture()?;
            store
                .connection
                .pragma_update(None, "foreign_keys", false)?;
            copy_edge(&store, "unattached", site, SOURCE, TARGET)?;
            validate_scan_graph(&store.connection, SCAN)?;
            store
                .connection
                .execute("UPDATE edges SET precision=x'ff' WHERE id='unattached'", [])?;
            assert!(
                validate_scan_graph(&store.connection, SCAN).is_err(),
                "{site:?}"
            );
        }
        let store = fixture()?;
        store
            .connection
            .pragma_update(None, "foreign_keys", false)?;
        store.connection.execute("DELETE FROM sites", [])?;
        validate_scan_graph(&store.connection, SCAN)?;
        store
            .connection
            .execute("UPDATE edges SET precision=x'ff'", [])?;
        assert!(validate_scan_graph(&store.connection, SCAN).is_err());
        Ok(())
    }

    #[test]
    fn sentinel_lookup_preserves_sqlite_id_types_and_error_precedence() -> Result<()> {
        let store = fixture()?;
        store.connection.execute(
            "INSERT INTO nodes(scan_id,id,kind,locator,display_name,properties_json,raw_json)
             VALUES(?1,CAST(?2 AS BLOB),'external_system','unused','unused','{}','{}')",
            params![SCAN, TARGET],
        )?;
        store.connection.execute(
            "INSERT INTO nodes(scan_id,id,kind,locator,display_name,properties_json,raw_json)
             VALUES(?1,CAST(x'ff' AS TEXT),'unknown_target','unused','unused','{}','{}')",
            [SCAN],
        )?;
        validate_scan_graph(&store.connection, SCAN)?;
        store
            .connection
            .execute("UPDATE sites SET target_ids_json='[]'", [])?;
        store.connection.execute(
            "UPDATE nodes SET kind='external_system' WHERE id=?1",
            [TARGET],
        )?;
        assert!(error_text(&store).contains("1 invalid resolution target classifications"));
        Ok(())
    }
}
