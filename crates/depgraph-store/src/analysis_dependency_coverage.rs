//! Small, derived dependency-scope proof for health. The durable ledger stays
//! the source of truth and is already covered by the completed snapshot seal.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};

use crate::{AnalysisDependencyCoverage, table_exists};

/// Retain only adapter-level unknown dependency flags, charging each row and
/// never loading source paths or other potentially large ledger payloads.
/// Missing or unfamiliar proof cannot justify narrowing a coverage blocker.
pub(crate) fn load_analysis_dependency_coverage(
    connection: &Connection,
    scan_id: &str,
    mut charge: impl FnMut() -> Result<()>,
) -> Result<Option<AnalysisDependencyCoverage>> {
    // Historical Store migrations validate snapshots before the analysis
    // tables are created. Their absence cannot provide dependency scope.
    charge()?;
    if !table_exists(connection, "analysis_scan_metadata")? {
        return Ok(None);
    }
    charge()?;
    if !table_exists(connection, "analysis_unit_ledger")? {
        return Ok(None);
    }
    charge()?;
    let metadata = connection
        .query_row(
            "SELECT contract_version, plan_id, input_digest
               FROM analysis_scan_metadata WHERE scan_id=?1",
            [scan_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((contract, Some(plan), Some(input))) = metadata else {
        return Ok(None);
    };
    if !matches!(
        contract.as_str(),
        "depgraph-analysis-unit-v1" | "depgraph-analysis-unit-v2"
    ) || plan.is_empty()
        || input.is_empty()
    {
        return Ok(None);
    }
    let mut statement = connection.prepare(
        "SELECT contract_version, adapter, status, unknown_dependencies
           FROM analysis_unit_ledger WHERE scan_id=?1",
    )?;
    let mut rows = statement.query([scan_id])?;
    let mut coverage = AnalysisDependencyCoverage::default();
    while let Some(row) = rows.next()? {
        charge()?;
        let row_contract: String = row.get(0)?;
        let adapter: String = row.get(1)?;
        let status: String = row.get(2)?;
        let unknown: i64 = row.get(3)?;
        if row_contract != contract
            || !AnalysisDependencyCoverage::KNOWN_ADAPTERS.contains(&adapter.as_str())
            || status != "completed"
            || !matches!(unknown, 0 | 1)
        {
            return Ok(None);
        }
        *coverage.unknown_dependencies.entry(adapter).or_default() |= unknown == 1;
    }
    Ok((!coverage.unknown_dependencies.is_empty()).then_some(coverage))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<Connection> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE analysis_scan_metadata(scan_id TEXT, contract_version TEXT, plan_id TEXT, input_digest TEXT);
             CREATE TABLE analysis_unit_ledger(scan_id TEXT, contract_version TEXT, adapter TEXT, status TEXT, unknown_dependencies INTEGER);
             INSERT INTO analysis_scan_metadata VALUES ('scan', 'depgraph-analysis-unit-v2', 'plan', 'input');
             INSERT INTO analysis_unit_ledger VALUES
               ('scan', 'depgraph-analysis-unit-v2', 'go', 'completed', 0),
               ('scan', 'depgraph-analysis-unit-v2', 'web', 'completed', 0),
               ('scan', 'depgraph-analysis-unit-v2', 'web', 'completed', 1);",
        )?;
        Ok(connection)
    }

    #[test]
    fn dependency_scope_joins_all_rows_and_charges_bounded_work() -> Result<()> {
        let connection = fixture()?;
        let mut work = 0;
        let coverage = load_analysis_dependency_coverage(&connection, "scan", || {
            work += 1;
            Ok(())
        })?
        .unwrap();
        assert_eq!(work, 6);
        assert_eq!(
            coverage.unknown_dependencies,
            std::collections::BTreeMap::from([("go".into(), false), ("web".into(), true),])
        );
        let error = load_analysis_dependency_coverage(&connection, "scan", || {
            anyhow::bail!("budget exhausted")
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "budget exhausted");
        Ok(())
    }

    #[test]
    fn dependency_scope_rejects_missing_incomplete_or_unfamiliar_proof() -> Result<()> {
        for mutation in [
            "DROP TABLE analysis_scan_metadata",
            "DROP TABLE analysis_unit_ledger",
            "DELETE FROM analysis_scan_metadata",
            "DELETE FROM analysis_unit_ledger",
            "UPDATE analysis_scan_metadata SET plan_id=NULL",
            "UPDATE analysis_scan_metadata SET input_digest=''",
            "UPDATE analysis_scan_metadata SET contract_version='future'",
            "UPDATE analysis_unit_ledger SET contract_version='depgraph-analysis-unit-v1' WHERE adapter='web'",
            "UPDATE analysis_unit_ledger SET adapter='future' WHERE adapter='web'",
            "UPDATE analysis_unit_ledger SET status='failed' WHERE adapter='web'",
            "UPDATE analysis_unit_ledger SET status='running' WHERE adapter='web'",
            "UPDATE analysis_unit_ledger SET unknown_dependencies=2 WHERE adapter='web'",
        ] {
            let connection = fixture()?;
            connection.execute_batch(mutation)?;
            assert!(
                load_analysis_dependency_coverage(&connection, "scan", || Ok(()))?.is_none(),
                "{mutation}"
            );
        }
        Ok(())
    }
}
