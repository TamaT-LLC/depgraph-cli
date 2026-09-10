//! Check every main-schema foreign key without reading large graph payloads.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::Connection;

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ForeignKey {
    parent: String,
    columns: Vec<(String, Option<String>)>,
}

impl ForeignKey {
    fn new(parent: &str, columns: &[(&str, &str)]) -> Self {
        Self {
            parent: parent.to_owned(),
            columns: columns
                .iter()
                .map(|(child, parent)| ((*child).to_owned(), Some((*parent).to_owned())))
                .collect(),
        }
    }
}

pub(crate) fn count_violations(connection: &Connection) -> Result<u64> {
    // The old single PRAGMA held one read snapshot. Keep the same guarantee
    // across the replacement queries, including during migration transactions.
    let transaction = connection
        .is_autocommit()
        .then(|| connection.unchecked_transaction())
        .transpose()?;
    let violations = count_violations_in_transaction(connection)?;
    if let Some(transaction) = transaction {
        transaction.commit()?;
    }
    Ok(violations)
}

fn count_violations_in_transaction(connection: &Connection) -> Result<u64> {
    debug_assert!(!connection.is_autocommit());
    let tables = connection
        .prepare("SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    // Preparing the native PRAGMA validates parent keys and their unique
    // indexes, even for empty tables. Do not step it: that reads all payloads.
    // The preceding schema read already established this transaction's snapshot.
    drop(connection.prepare("PRAGMA main.foreign_key_check")?);

    let mut violations = 0_u64;
    let mut native_tables = Vec::new();
    for table in tables {
        if let Some((phase, sql)) = covering_check(connection, &table)? {
            let count = crate::profiling::run(phase, || {
                Ok(connection.query_row(&sql, [], |row| row.get::<_, u64>(0))?)
            })?;
            violations = violations
                .checked_add(count)
                .context("foreign key violation count overflowed")?;
        } else {
            native_tables.push(table);
        }
    }
    crate::profiling::run("store-foreign-key-other", || {
        for table in native_tables {
            let count = connection.query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_check(?1, 'main')",
                [table],
                |row| row.get::<_, u64>(0),
            )?;
            violations = violations
                .checked_add(count)
                .context("foreign key violation count overflowed")?;
        }
        Ok(violations)
    })
}

fn covering_check(connection: &Connection, table: &str) -> Result<Option<(&'static str, String)>> {
    let phase = match table {
        "nodes" => "store-foreign-key-nodes",
        "sites" => "store-foreign-key-sites",
        "edges" => "store-foreign-key-edges",
        "evidence" => "store-foreign-key-evidence",
        _ => return Ok(None),
    };
    let mut expected = vec![ForeignKey::new("scans", &[("scan_id", "id")])];
    if table == "edges" {
        expected.push(ForeignKey::new(
            "sites",
            &[("scan_id", "scan_id"), ("site_id", "id")],
        ));
    }
    expected.sort();
    if foreign_keys(connection, table)? != expected
        || !has_text_columns(connection, "scans", &["id"])?
        || (table == "edges" && !has_text_columns(connection, "sites", &["scan_id", "id"])?)
    {
        return Ok(None);
    }

    // Only the fixed table names above reach this interpolation. Unary +
    // removes the CHILD column's affinity without changing its value: foreign
    // keys always apply the parent's affinity and collation. Plain parent=child
    // would incorrectly let a NUMERIC child match a TEXT parent such as '001'.
    let scan_check = format!(
        "SELECT COUNT(*) FROM main.\"{table}\" AS child
          WHERE +child.scan_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM main.scans AS parent
                             WHERE parent.id=+child.scan_id)"
    );
    let sql = if table == "edges" {
        // Each violated constraint counts separately. A row with a missing
        // scan and a missing site contributes two, just like foreign_key_check.
        format!(
            "SELECT ({scan_check}) + (
                SELECT COUNT(*) FROM main.edges AS child
                 WHERE +child.scan_id IS NOT NULL AND +child.site_id IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM main.sites AS parent
                                    WHERE parent.scan_id=+child.scan_id
                                      AND parent.id=+child.site_id)
             )"
        )
    } else {
        scan_check
    };
    Ok(Some((phase, sql)))
}

fn foreign_keys(connection: &Connection, table: &str) -> Result<Vec<ForeignKey>> {
    let mut statement = connection.prepare(
        "SELECT id, \"table\", \"from\", \"to\"
           FROM pragma_foreign_key_list(?1, 'main') ORDER BY id, seq",
    )?;
    let rows = statement.query_map([table], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut groups = BTreeMap::<i64, ForeignKey>::new();
    for row in rows {
        let (id, parent, child, target) = row?;
        groups
            .entry(id)
            .or_insert_with(|| ForeignKey {
                parent,
                columns: Vec::new(),
            })
            .columns
            .push((child, target));
    }
    let mut groups = groups.into_values().collect::<Vec<_>>();
    groups.sort();
    Ok(groups)
}

fn has_text_columns(connection: &Connection, table: &str, columns: &[&str]) -> Result<bool> {
    let actual = connection
        .prepare(
            "SELECT name FROM pragma_table_xinfo(?1, 'main')
              WHERE upper(type)='TEXT' AND hidden=0",
        )?
        .query_map([table], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns
        .iter()
        .all(|column| actual.iter().any(|name| name == column)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use rusqlite::{params, types::Value};

    fn corruptible_fixture() -> Result<Connection> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", false)?;
        Ok(connection)
    }

    fn native_count(connection: &Connection) -> Result<u64> {
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_check(NULL, 'main')",
            [],
            |row| row.get(0),
        )?)
    }

    fn assert_same_count(connection: &Connection, expected: u64) -> Result<()> {
        assert_eq!(native_count(connection)?, expected);
        assert_eq!(count_violations(connection)?, expected);
        Ok(())
    }

    #[test]
    fn graph_checks_use_covering_indexes_on_the_store_schema() -> Result<()> {
        let store = Store::open_in_memory()?;
        for table in ["nodes", "sites", "edges", "evidence"] {
            let (_, sql) = covering_check(&store.connection, table)?.unwrap();
            let plan = store
                .connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?
                .query_map([], |row| row.get::<_, String>(3))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let child_scans = plan
                .iter()
                .filter(|step| step.starts_with("SCAN child"))
                .collect::<Vec<_>>();
            assert_eq!(child_scans.len(), if table == "edges" { 2 } else { 1 });
            assert!(
                child_scans
                    .iter()
                    .all(|step| step.contains("COVERING INDEX")),
                "{table}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .filter(|step| step.starts_with("SEARCH parent"))
                    .all(|step| step.contains("COVERING INDEX")),
                "{table}: {plan:?}"
            );
        }
        assert_same_count(&store.connection, 0)
    }

    #[test]
    fn counts_all_history_and_each_violated_constraint_including_native_tables() -> Result<()> {
        let connection = corruptible_fixture()?;
        connection.execute_batch(
            "CREATE TABLE scans(id TEXT PRIMARY KEY);
             CREATE TABLE sites(scan_id TEXT REFERENCES scans(id), id TEXT,
                                PRIMARY KEY(scan_id,id));
             CREATE TABLE nodes(scan_id TEXT REFERENCES scans(id));
             CREATE TABLE evidence(scan_id TEXT REFERENCES scans(id));
             CREATE TABLE edges(scan_id TEXT REFERENCES scans(id), site_id TEXT,
                                FOREIGN KEY(scan_id,site_id) REFERENCES sites(scan_id,id));
             CREATE TABLE other_history(scan_id TEXT REFERENCES scans(id));
             INSERT INTO scans VALUES('current'),('historical');
             INSERT INTO sites VALUES('current','present'),('historical','present');
             INSERT INTO nodes VALUES('current'),('historical'),(NULL),('missing-a'),('missing-b');
             INSERT INTO evidence VALUES('missing-c');
             INSERT INTO sites VALUES('missing-d','orphan');
             INSERT INTO edges VALUES('current','absent'),('missing-e','absent'),
                                     ('missing-f',NULL),('current',NULL),(NULL,'absent');
             INSERT INTO other_history VALUES('missing-g');",
        )?;
        for table in ["nodes", "sites", "edges", "evidence"] {
            assert!(covering_check(&connection, table)?.is_some());
        }
        assert_same_count(&connection, 9)
    }

    #[test]
    fn parent_text_affinity_overrides_numeric_child_affinity() -> Result<()> {
        let connection = corruptible_fixture()?;
        connection.execute_batch(
            "CREATE TABLE scans(id TEXT PRIMARY KEY);
             CREATE TABLE nodes(scan_id NUMERIC REFERENCES scans(id));
             CREATE TABLE sites(scan_id TEXT REFERENCES scans(id), id TEXT,
                                PRIMARY KEY(scan_id,id));
             CREATE TABLE edges(scan_id NUMERIC REFERENCES scans(id), site_id NUMERIC,
                                FOREIGN KEY(scan_id,site_id) REFERENCES sites(scan_id,id));
             INSERT INTO scans VALUES('001');
             INSERT INTO sites VALUES('001','002');
             INSERT INTO nodes VALUES(1);
             INSERT INTO edges VALUES(1,2);",
        )?;
        assert!(covering_check(&connection, "nodes")?.is_some());
        assert!(covering_check(&connection, "edges")?.is_some());
        // A plain column-to-column comparison incorrectly reports no violation.
        let plain: u64 = connection.query_row(
            "SELECT COUNT(*) FROM nodes child WHERE NOT EXISTS
                (SELECT 1 FROM scans parent WHERE parent.id=child.scan_id)",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(plain, 0);
        assert_same_count(&connection, 3)
    }

    #[test]
    fn parent_collation_and_storage_types_match_sqlite_for_single_and_composite_keys() -> Result<()>
    {
        let values = [
            Value::Null,
            Value::Integer(1),
            Value::Real(1.25),
            Value::Text("001".into()),
            Value::Text("alpha".into()),
            Value::Text("ALPHA".into()),
            Value::Text("alpha ".into()),
            Value::Text("日本語".into()),
            Value::Blob(b"alpha".to_vec()),
        ];
        for collation in ["BINARY", "NOCASE", "RTRIM"] {
            for affinity in ["TEXT", "NUMERIC", "BLOB"] {
                let connection = corruptible_fixture()?;
                connection.execute_batch(&format!(
                    "CREATE TABLE scans(id TEXT COLLATE {collation} PRIMARY KEY);
                     CREATE TABLE nodes(scan_id {affinity} COLLATE NOCASE REFERENCES scans(id));
                     CREATE TABLE sites(scan_id TEXT COLLATE {collation} REFERENCES scans(id),
                                        id TEXT COLLATE {collation}, PRIMARY KEY(scan_id,id));
                     CREATE TABLE edges(scan_id {affinity} COLLATE NOCASE REFERENCES scans(id),
                                        site_id {affinity} COLLATE NOCASE,
                                        FOREIGN KEY(scan_id,site_id) REFERENCES sites(scan_id,id));
                     INSERT INTO scans VALUES('001'),('alpha'),(X'616c706861');
                     INSERT INTO sites VALUES('001','alpha'),('alpha','001'),
                                             (X'616c706861',X'616c706861');"
                ))?;
                for value in &values {
                    connection.execute("INSERT INTO nodes VALUES(?1)", [value])?;
                    for site in &values {
                        connection
                            .execute("INSERT INTO edges VALUES(?1,?2)", params![value, site])?;
                    }
                }
                assert!(covering_check(&connection, "nodes")?.is_some());
                assert!(covering_check(&connection, "edges")?.is_some());
                assert_eq!(
                    count_violations(&connection)?,
                    native_count(&connection)?,
                    "parent {collation}, child {affinity}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn unexpected_foreign_keys_and_parent_shapes_use_the_native_check() -> Result<()> {
        for schema in [
            "CREATE TABLE scans(id TEXT PRIMARY KEY);
             CREATE TABLE extra(id TEXT PRIMARY KEY);
             CREATE TABLE nodes(scan_id TEXT REFERENCES scans(id), other TEXT REFERENCES extra(id));
             INSERT INTO scans VALUES('valid');
             INSERT INTO nodes VALUES('valid','missing');",
            "CREATE TABLE scans(id INTEGER PRIMARY KEY);
             CREATE TABLE nodes(scan_id TEXT REFERENCES scans(id));
             INSERT INTO scans VALUES(1);
             INSERT INTO nodes VALUES('001'),('missing');",
            "CREATE TABLE scans(id TEXT PRIMARY KEY);
             CREATE TABLE nodes(scan_id TEXT REFERENCES scans);
             INSERT INTO nodes VALUES('missing');",
            "CREATE TABLE nodes(scan_id TEXT REFERENCES scans(id));
             INSERT INTO nodes VALUES('missing'),(NULL);",
        ] {
            let connection = corruptible_fixture()?;
            connection.execute_batch(schema)?;
            assert!(covering_check(&connection, "nodes")?.is_none());
            assert_same_count(&connection, 1)?;
        }
        Ok(())
    }

    #[test]
    fn invalid_parent_unique_indexes_fail_even_when_children_are_empty() -> Result<()> {
        for schema in [
            "CREATE TABLE scans(id TEXT);
             CREATE TABLE nodes(scan_id TEXT REFERENCES scans(id));",
            "CREATE TABLE scans(id TEXT COLLATE BINARY);
             CREATE UNIQUE INDEX scans_id ON scans(id COLLATE NOCASE);
             CREATE TABLE nodes(scan_id TEXT REFERENCES scans(id));",
            "CREATE TABLE scans(id TEXT PRIMARY KEY);
             CREATE TABLE nodes(scan_id TEXT REFERENCES scans(missing));",
        ] {
            let connection = corruptible_fixture()?;
            connection.execute_batch(schema)?;
            let native_error = native_count(&connection).unwrap_err().to_string();
            let error = count_violations(&connection).unwrap_err().to_string();
            assert!(
                native_error.contains("foreign key mismatch"),
                "{native_error}"
            );
            assert_eq!(error, native_error);
            assert!(connection.is_autocommit());
        }
        Ok(())
    }

    #[test]
    fn main_schema_checks_ignore_temp_shadows_and_preserve_caller_transactions() -> Result<()> {
        let connection = corruptible_fixture()?;
        connection.execute_batch(
            "CREATE TABLE scans(id TEXT PRIMARY KEY);
             CREATE TABLE nodes(scan_id TEXT REFERENCES scans(id));
             CREATE TABLE \"quoted \"\" child\"(scan_id TEXT REFERENCES scans(id));
             INSERT INTO nodes VALUES('missing');
             INSERT INTO \"quoted \"\" child\" VALUES('missing');
             CREATE TEMP TABLE scans(id TEXT PRIMARY KEY);
             CREATE TEMP TABLE nodes(scan_id TEXT REFERENCES scans(id));
             INSERT INTO temp.scans VALUES('missing');
             ATTACH DATABASE ':memory:' AS other;
             CREATE TABLE other.child(scan_id TEXT REFERENCES missing(id));
             INSERT INTO other.child VALUES('missing');",
        )?;
        assert_same_count(&connection, 2)?;
        assert!(connection.is_autocommit());
        connection.execute_batch("BEGIN; INSERT INTO main.scans VALUES('missing');")?;
        assert_same_count(&connection, 0)?;
        assert!(!connection.is_autocommit());
        connection.execute_batch("ROLLBACK;")?;
        assert_same_count(&connection, 2)?;
        Ok(())
    }
}
