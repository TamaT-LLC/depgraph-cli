//! Reconstruct aggregate completeness without changing individual profiles.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

use crate::{AnalysisCoverageSummary, AnalysisUnitLedgerRecord, ProfileRecord};

/// Derive the conservative repository-level analysis coverage from durable
/// unit rows.  This function intentionally does not infer a missing stage or
/// chunk from profile coverage: a unit is complete only when every required
/// stage/chunk is present, terminally completed, and bound to the same input
/// context.
pub fn aggregate_analysis_coverage(
    contract_version: &str,
    plan_id: Option<&str>,
    input_digest: Option<&str>,
    records: &[AnalysisUnitLedgerRecord],
) -> AnalysisCoverageSummary {
    let mut units = BTreeMap::<(String, String), Vec<&AnalysisUnitLedgerRecord>>::new();
    for record in records {
        units
            .entry((record.unit_id.clone(), record.unit_root.clone()))
            .or_default()
            .push(record);
    }

    let mut completed_units = 0_u64;
    let mut failed_units = 0_u64;
    let mut unanalysed_units = 0_u64;
    let mut cancelled_units = 0_u64;
    let mut semantic_complete_units = 0_u64;
    let mut reasons = BTreeSet::new();

    for rows in units.values() {
        let statuses = rows
            .iter()
            .map(|row| row.status.as_str())
            .collect::<BTreeSet<_>>();
        if statuses.contains("failed") {
            failed_units += 1;
            reasons.insert("analysis-unit-failed".to_owned());
            continue;
        }
        if statuses.contains("cancelled") {
            cancelled_units += 1;
            reasons.insert("analysis-unit-cancelled".to_owned());
            continue;
        }
        if statuses
            .iter()
            .any(|status| matches!(*status, "queued" | "running" | "unanalysed" | "unknown"))
        {
            unanalysed_units += 1;
            reasons.insert("analysis-unit-unanalysed".to_owned());
            continue;
        }

        let contracts = rows
            .iter()
            .map(|row| row.contract_version.as_str())
            .collect::<BTreeSet<_>>();
        if contracts.len() != 1 {
            unanalysed_units += 1;
            reasons.insert("analysis-unit-contract-mismatch".to_owned());
            continue;
        }
        let contract = *contracts.first().unwrap_or(&contract_version);
        let stages = rows
            .iter()
            .map(|row| row.stage.as_str())
            .collect::<BTreeSet<_>>();
        let joined = match contract {
            "depgraph-analysis-unit-v1" => join_v1(rows, &stages, &mut reasons),
            "depgraph-analysis-unit-v2" => join_v2(rows, &stages, &mut reasons),
            // Repository-wide legacy workers have no stage pair.  Their
            // established scan validation remains the source of truth, but a
            // ledger row with an unknown dependency is still conservative.
            _ if stages == BTreeSet::from(["repository"]) => {
                rows.len() == 1 && rows[0].status == "completed" && !rows[0].unknown_dependencies
            }
            _ => {
                reasons.insert("analysis-unit-unknown-contract".to_owned());
                false
            }
        };
        if joined {
            completed_units += 1;
            semantic_complete_units += 1;
        } else {
            unanalysed_units += 1;
        }
    }

    let expected_units = units.len() as u64;
    if expected_units == 0 {
        reasons.insert("analysis-unit-plan-empty".to_owned());
    }
    let complete = expected_units == 0 || completed_units == expected_units;
    if !complete {
        reasons.insert("analysis-unit-incomplete".to_owned());
    }
    AnalysisCoverageSummary {
        contract_version: contract_version.to_owned(),
        plan_id: plan_id.map(ToOwned::to_owned),
        input_digest: input_digest.map(ToOwned::to_owned),
        expected_units,
        completed_units,
        failed_units,
        unanalysed_units,
        cancelled_units,
        semantic_complete_units,
        complete,
        reasons: reasons.into_iter().collect(),
    }
}

fn join_v1(
    rows: &[&AnalysisUnitLedgerRecord],
    stages: &BTreeSet<&str>,
    reasons: &mut BTreeSet<String>,
) -> bool {
    if stages != &BTreeSet::from(["semantic", "syntax"]) || rows.len() != 2 {
        reasons.insert("analysis-unit-missing-stage".to_owned());
        return false;
    }
    let syntax = rows.iter().find(|row| row.stage == "syntax");
    let semantic = rows.iter().find(|row| row.stage == "semantic");
    let (Some(syntax), Some(semantic)) = (syntax, semantic) else {
        reasons.insert("analysis-unit-missing-stage".to_owned());
        return false;
    };
    if !rows.iter().all(|row| row.status == "completed") {
        reasons.insert("analysis-unit-stage-incomplete".to_owned());
        return false;
    }
    if !syntax.chunk_id.is_empty()
        || !semantic.chunk_id.is_empty()
        || syntax.chunk_index.is_some()
        || semantic.chunk_index.is_some()
        || syntax.chunk_count.is_some()
        || semantic.chunk_count.is_some()
    {
        reasons.insert("analysis-unit-v1-chunk-metadata".to_owned());
        return false;
    }
    same_context(syntax, semantic, reasons)
        && !syntax.unknown_dependencies
        && !semantic.unknown_dependencies
}

fn join_v2(
    rows: &[&AnalysisUnitLedgerRecord],
    stages: &BTreeSet<&str>,
    reasons: &mut BTreeSet<String>,
) -> bool {
    let expect_typed = if stages == &BTreeSet::from(["semantic", "syntax"]) {
        false
    } else if stages == &BTreeSet::from(["semantic", "syntax", "typed"]) {
        true
    } else {
        reasons.insert("analysis-unit-missing-stage".to_owned());
        return false;
    };
    let typed_rows = rows
        .iter()
        .filter(|row| row.stage == "typed")
        .copied()
        .collect::<Vec<_>>();
    if expect_typed && typed_rows.iter().any(|row| row.adapter != "go") {
        reasons.insert("analysis-unit-typed-adapter-mismatch".to_owned());
        return false;
    }
    if expect_typed && !valid_chunks(&typed_rows, reasons) {
        return false;
    }
    let syntax = rows
        .iter()
        .filter(|row| row.stage == "syntax")
        .copied()
        .collect::<Vec<_>>();
    let semantic = rows
        .iter()
        .filter(|row| row.stage == "semantic")
        .copied()
        .collect::<Vec<_>>();
    if !valid_chunks(&syntax, reasons) || !valid_chunks(&semantic, reasons) {
        return false;
    }
    if syntax.iter().any(|row| row.status != "completed")
        || semantic.iter().any(|row| row.status != "completed")
        || typed_rows.iter().any(|row| row.status != "completed")
    {
        reasons.insert("analysis-unit-stage-incomplete".to_owned());
        return false;
    }
    if syntax.iter().any(|row| row.unknown_dependencies)
        || semantic.iter().any(|row| row.unknown_dependencies)
        || typed_rows.iter().any(|row| row.unknown_dependencies)
    {
        reasons.insert("analysis-unit-unknown-dependency".to_owned());
        return false;
    }

    let owned_sources = union_paths(&syntax, |row| &row.source_paths);
    let declared_context = union_paths(&syntax, |row| &row.context_paths);
    // Context includes dependency sources which the unit must resolve but
    // must never claim as its own output. Every chunk sees the same context,
    // and both output stages must cover the same disjoint owned source set.
    if !owned_sources.is_subset(&declared_context)
        || union_paths(&semantic, |row| &row.source_paths) != owned_sources
        || [&syntax, &semantic].into_iter().any(|stage| {
            stage
                .iter()
                .map(|row| row.source_paths.len())
                .sum::<usize>()
                != owned_sources.len()
        })
    {
        reasons.insert("analysis-unit-context-scope-mismatch".to_owned());
        return false;
    }
    if syntax.iter().chain(semantic.iter()).any(|row| {
        union_paths(std::slice::from_ref(row), |item| &item.context_paths) != declared_context
    }) {
        reasons.insert("analysis-unit-context-scope-mismatch".to_owned());
        return false;
    }
    // Go's typed stage receives the owned module as its context and
    // go/packages reconstructs dependency types; the shared fingerprint still
    // binds its external dependency inputs.  A module-loader worker types the
    // whole module in one request; a package-loader worker types it as
    // package-bounded rows.  Either way the typed rows must partition exactly
    // the owned sources: every row sees the same module context, no owned
    // source is typed twice, and none is left untyped.
    if expect_typed
        && (typed_rows.iter().any(|row| {
            union_paths(std::slice::from_ref(row), |item| &item.context_paths) != owned_sources
        }) || union_paths(&typed_rows, |row| &row.source_paths) != owned_sources
            || typed_rows
                .iter()
                .map(|row| row.source_paths.len())
                .sum::<usize>()
                != owned_sources.len())
    {
        reasons.insert("analysis-unit-context-scope-mismatch".to_owned());
        return false;
    }
    let fingerprints = syntax
        .iter()
        .chain(typed_rows.iter())
        .chain(semantic.iter())
        .filter_map(|row| row.context_fingerprint.as_deref())
        .collect::<BTreeSet<_>>();
    if fingerprints.len() != 1
        || semantic
            .iter()
            .any(|row| row.context_fingerprint.as_deref() != fingerprints.first().copied())
        || typed_rows
            .iter()
            .any(|row| row.context_fingerprint.as_deref() != fingerprints.first().copied())
    {
        reasons.insert("analysis-unit-context-fingerprint-mismatch".to_owned());
        return false;
    }
    true
}

fn valid_chunks(rows: &[&AnalysisUnitLedgerRecord], reasons: &mut BTreeSet<String>) -> bool {
    if rows.is_empty() {
        reasons.insert("analysis-unit-missing-stage".to_owned());
        return false;
    }
    // Retained batches keep their creation-generation count. The newest
    // refinement owns the highest count; its active slots must still form
    // one complete, unique partition. A count alone never proves completion.
    let Some(expected) = rows.iter().filter_map(|row| row.chunk_count).max() else {
        reasons.insert("analysis-unit-chunk-metadata".to_owned());
        return false;
    };
    if expected == 0 || rows.len() != expected as usize {
        reasons.insert("analysis-unit-chunk-count-mismatch".to_owned());
        return false;
    }
    let mut indices = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for row in rows {
        // A manifest-only project can legitimately produce one empty batch:
        // there are no source paths to list, while the worker still records
        // the unit and its context fingerprint.  Keep the exception narrow
        // so an empty context cannot make a multi-batch or otherwise scoped
        // result look complete.
        let empty_manifest_batch =
            expected == 1 && row.source_paths.is_empty() && row.context_paths.is_empty();
        if !row.chunk_count.is_some_and(|count| {
            count > 0 && count <= expected && row.chunk_index.is_some_and(|index| index < count)
        }) || row.chunk_id.is_empty()
            || (!empty_manifest_batch && row.context_paths.is_empty())
        {
            reasons.insert("analysis-unit-chunk-metadata".to_owned());
            return false;
        }
        if !indices.insert(row.chunk_index.unwrap_or_default())
            || !ids.insert(row.chunk_id.as_str())
        {
            reasons.insert("analysis-unit-duplicate-chunk".to_owned());
            return false;
        }
    }
    if indices != (0..expected).collect::<BTreeSet<_>>() {
        reasons.insert("analysis-unit-chunk-index-gap".to_owned());
        return false;
    }
    true
}

fn same_context(
    left: &AnalysisUnitLedgerRecord,
    right: &AnalysisUnitLedgerRecord,
    reasons: &mut BTreeSet<String>,
) -> bool {
    let same = left.context_paths == right.context_paths
        && left.context_fingerprint == right.context_fingerprint
        && left.source_paths == right.source_paths;
    if !same {
        reasons.insert("analysis-unit-context-mismatch".to_owned());
    }
    same
}

fn union_paths<'a, F>(rows: &[&'a AnalysisUnitLedgerRecord], paths: F) -> BTreeSet<String>
where
    F: Fn(&'a AnalysisUnitLedgerRecord) -> &'a [String],
{
    rows.iter()
        .flat_map(|row| paths(row).iter().cloned())
        .collect()
}

pub(crate) fn aggregate_completeness(
    profiles: &[ProfileRecord],
    analysis_records: Option<&[AnalysisUnitLedgerRecord]>,
) -> Result<Option<BTreeSet<String>>> {
    let mut levels = profiles
        .iter()
        .map(|profile| {
            profile
                .coverage
                .as_ref()
                .with_context(|| format!("profile {} has no coverage", profile.id))
                .map(|coverage| {
                    coverage
                        .completeness
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                })
        })
        .collect::<Result<Vec<_>>>()?;
    // A logical unit can be analyzed under several selected configurations.
    // Keep each profile's stage pair/triple together; joining every profile
    // for the unit at once would incorrectly reject a valid multi-profile
    // result as a duplicate stage.
    // Go base IDs also incorporate the typed dependency snapshot, which is
    // unavailable during syntax analysis. Join stages by configuration axes;
    // the durable ledger independently proves their identical input context.
    let mut units = BTreeMap::<(&str, &str, String), Vec<(usize, &str, &str)>>::new();
    for (index, profile) in profiles.iter().enumerate() {
        let Some(contract) = profile.properties["analysis_unit_contract"].as_str() else {
            continue;
        };
        if !matches!(
            contract,
            "depgraph-analysis-unit-v1" | "depgraph-analysis-unit-v2"
        ) {
            continue;
        }
        if contract == "depgraph-analysis-unit-v1" && profile.language != "go" {
            bail!("analysis-unit v1 coverage is only supported for Go");
        }
        let field = |key: &str| {
            profile.properties[key]
                .as_str()
                .filter(|value| !value.is_empty())
                .with_context(|| format!("analysis-unit profile {} has no {key}", profile.id))
        };
        let unit = field("analysis_unit_id")?;
        let root = field("analysis_unit_root")?;
        let stage = field("analysis_stage")?;
        if !matches!(stage, "syntax" | "typed" | "semantic") {
            bail!("analysis-unit profile {} has an unknown stage", profile.id);
        }
        if stage == "typed" && (profile.language != "go" || contract != "depgraph-analysis-unit-v2")
        {
            bail!("typed analysis-unit coverage requires Go analysis-unit v2");
        }
        units
            .entry((
                unit,
                root,
                depgraph_protocol::canonical_json(&profile_axes(profile)),
            ))
            .or_default()
            .push((index, stage, contract));
    }
    for stages in units.values() {
        // An unmatched, duplicated, or incompatible stage cannot establish
        // aggregate semantic completeness, even if one profile claims it.
        let grouped = stages
            .iter()
            .map(|(index, _, _)| &profiles[*index])
            .collect::<Vec<_>>();
        let joined = complete_analysis_profile_group(&grouped, analysis_records);
        for (index, _, _) in stages {
            levels[*index].remove("semantic-complete");
            if joined {
                levels[*index].insert("semantic-complete".into());
            }
        }
    }
    let mut levels = levels.into_iter();
    let Some(mut intersection) = levels.next() else {
        return Ok(None);
    };
    for profile in levels {
        intersection.retain(|level| profile.contains(level));
    }
    Ok(Some(intersection))
}

fn complete_analysis_profile_group(
    profiles: &[&ProfileRecord],
    analysis_records: Option<&[AnalysisUnitLedgerRecord]>,
) -> bool {
    let contracts = profiles
        .iter()
        .filter_map(|profile| profile.properties["analysis_unit_contract"].as_str())
        .collect::<BTreeSet<_>>();
    let Some(contract) = contracts.first().copied() else {
        return false;
    };
    if contracts.len() != 1 {
        return false;
    }
    let stages = profiles
        .iter()
        .filter_map(|profile| profile.properties["analysis_stage"].as_str())
        .collect::<BTreeSet<_>>();
    let valid_shape = match contract {
        "depgraph-analysis-unit-v1" | "depgraph-analysis-unit-v2"
            if profiles.len() == 2 && stages == BTreeSet::from(["semantic", "syntax"]) =>
        {
            true
        }
        "depgraph-analysis-unit-v2"
            if profiles.len() == 3 && stages == BTreeSet::from(["semantic", "syntax", "typed"]) =>
        {
            true
        }
        _ => false,
    };
    if !valid_shape {
        return false;
    }
    let syntax = profiles
        .iter()
        .find(|profile| profile.properties["analysis_stage"] == "syntax");
    let typed = profiles
        .iter()
        .find(|profile| profile.properties["analysis_stage"] == "typed");
    let semantic = profiles
        .iter()
        .find(|profile| profile.properties["analysis_stage"] == "semantic");
    let (Some(syntax), Some(semantic)) = (syntax, semantic) else {
        return false;
    };
    if !same_axes(syntax, semantic)
        || !profile_has_level(syntax, "syntax-complete")
        || !profile_has_level(semantic, "semantic-complete")
    {
        return false;
    }
    if let Some(typed) = typed
        && (!typed_stage_complete(typed)
            || !profile_has_level(typed, "syntax-complete")
            || !same_axes(syntax, typed)
            || typed.properties["analysis_base_profile_id"]
                != semantic.properties["analysis_base_profile_id"])
    {
        return false;
    }
    let unit_id = syntax.properties["analysis_unit_id"]
        .as_str()
        .unwrap_or_default();
    let unit_root = syntax.properties["analysis_unit_root"]
        .as_str()
        .unwrap_or_default();
    match contract {
        "depgraph-analysis-unit-v2" => {
            analysis_records.is_some_and(|records| v2_ledger_joined(records, unit_id, unit_root))
        }
        // v1 predates the durable ledger requirement. When a ledger is
        // present, still require it; direct callers without one retain the
        // established profile-only behavior.
        "depgraph-analysis-unit-v1" => analysis_records
            .is_none_or(|records| ledger_joined(records, unit_id, unit_root, contract)),
        _ => false,
    }
}

fn v2_ledger_joined(records: &[AnalysisUnitLedgerRecord], unit_id: &str, unit_root: &str) -> bool {
    let rows = records
        .iter()
        .filter(|record| {
            record.contract_version == "depgraph-analysis-unit-v2"
                && record.unit_id == unit_id
                && record.unit_root == unit_root
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return false;
    }
    let stages = rows
        .iter()
        .map(|record| record.stage.as_str())
        .collect::<BTreeSet<_>>();
    let mut reasons = BTreeSet::new();
    join_v2(&rows, &stages, &mut reasons)
}

/// Count units whose execution ledger and persisted profile coverage both
/// establish semantic completeness. A terminal unit is not enough: workers
/// may complete successfully while reporting that semantic analysis was
/// unavailable for the unit.
pub(crate) fn semantic_complete_units(
    profiles: &[ProfileRecord],
    analysis_records: Option<&[AnalysisUnitLedgerRecord]>,
) -> u64 {
    let mut units = BTreeMap::<(String, String, String), Vec<&ProfileRecord>>::new();
    for profile in profiles {
        let Some(contract) = profile.properties["analysis_unit_contract"].as_str() else {
            continue;
        };
        if !matches!(
            contract,
            "depgraph-analysis-unit-v1" | "depgraph-analysis-unit-v2"
        ) {
            continue;
        }
        let (Some(unit), Some(root)) = (
            profile.properties["analysis_unit_id"].as_str(),
            profile.properties["analysis_unit_root"].as_str(),
        ) else {
            continue;
        };
        units
            .entry((
                unit.to_owned(),
                root.to_owned(),
                depgraph_protocol::canonical_json(&profile_axes(profile)),
            ))
            .or_default()
            .push(profile);
    }

    let mut logical_units = BTreeMap::<(String, String), Vec<bool>>::new();
    for ((unit, root, _axes), profiles) in units {
        let profile_refs = profiles.into_iter().collect::<Vec<_>>();
        let complete = complete_analysis_profile_group(&profile_refs, analysis_records);
        logical_units
            .entry((unit, root))
            .or_default()
            .push(complete);
    }
    logical_units
        .into_values()
        .filter(|groups| !groups.is_empty() && groups.iter().all(|complete| *complete))
        .count() as u64
}

fn ledger_joined(
    records: &[AnalysisUnitLedgerRecord],
    unit_id: &str,
    unit_root: &str,
    contract: &str,
) -> bool {
    let rows = records
        .iter()
        .filter(|record| {
            record.contract_version == contract
                && record.unit_id == unit_id
                && record.unit_root == unit_root
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return false;
    }
    let stages = rows
        .iter()
        .map(|record| record.stage.as_str())
        .collect::<BTreeSet<_>>();
    let mut reasons = BTreeSet::new();
    match contract {
        "depgraph-analysis-unit-v1" => join_v1(&rows, &stages, &mut reasons),
        "depgraph-analysis-unit-v2" => join_v2(&rows, &stages, &mut reasons),
        _ => false,
    }
}

fn profile_has_level(profile: &ProfileRecord, level: &str) -> bool {
    profile
        .coverage
        .as_ref()
        .is_some_and(|coverage| coverage.completeness.iter().any(|item| item == level))
}

fn typed_stage_complete(profile: &ProfileRecord) -> bool {
    profile.language == "go"
        && profile.properties["go_typed_stage_complete"].as_str() == Some("true")
}

fn same_axes(left: &ProfileRecord, right: &ProfileRecord) -> bool {
    profile_axes(left) == profile_axes(right)
}

fn profile_axes(profile: &ProfileRecord) -> serde_json::Value {
    let mut properties = [
        "parent_profile_id",
        "profile_selection_plan_id",
        "profile_selection_input_digest",
        "profile_selection_mode",
        "profile_selection_selected_profile_ids",
        "profile_selection_complete",
        "configured_tags",
        "go_call_graph_requested",
    ]
    .iter()
    .map(|key| ((*key).to_owned(), profile.properties[key].clone()))
    .collect::<serde_json::Map<_, _>>();
    if profile.language != "go" {
        properties.insert(
            "analysis_base_profile_id".to_owned(),
            profile.properties["analysis_base_profile_id"].clone(),
        );
    }
    serde_json::json!({
        "language": profile.language,
        "toolchain": profile.toolchain,
        "command": profile.command,
        "target": profile.target,
        "features": profile.features,
        "environment": profile.environment,
        "source_revision": profile.source_revision,
        "properties": properties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoverageRecord;
    use serde_json::json;

    fn profile(stage: &str) -> ProfileRecord {
        ProfileRecord {
            id: format!("profile:{stage}"),
            language: "go".into(),
            toolchain: Some(json!("go-test")),
            command: Some("scan".into()),
            target: Some("test-target".into()),
            features: Vec::new(),
            environment: json!({}),
            source_revision: None,
            properties: json!({
                "analysis_unit_contract":"depgraph-analysis-unit-v1",
                "analysis_unit_id":"unit", "analysis_unit_root":"app",
                "analysis_stage":stage,
            }),
            coverage: Some(CoverageRecord {
                profiles: 1,
                completeness: if stage == "syntax" {
                    vec!["syntax-complete".into()]
                } else {
                    vec!["syntax-complete".into(), "semantic-complete".into()]
                },
                ..CoverageRecord::default()
            }),
        }
    }

    fn v2_profile(stage: &str) -> ProfileRecord {
        let mut profile = profile(stage);
        profile.properties["analysis_unit_contract"] = json!("depgraph-analysis-unit-v2");
        profile.properties["analysis_base_profile_id"] = json!("go:base");
        profile
    }

    fn v2_typed_profile(complete: bool) -> ProfileRecord {
        let mut profile = v2_profile("typed");
        profile.properties["go_typed_stage_complete"] =
            json!(if complete { "true" } else { "false" });
        profile.coverage.as_mut().unwrap().completeness = vec!["syntax-complete".into()];
        profile
    }

    fn semantic(profiles: &[ProfileRecord]) -> Result<bool> {
        Ok(aggregate_completeness(profiles, None)?
            .is_some_and(|levels| levels.contains("semantic-complete")))
    }

    fn unit_row(
        stage: &str,
        chunk_id: &str,
        chunk_index: u64,
        chunk_count: u64,
        source_paths: &[&str],
    ) -> AnalysisUnitLedgerRecord {
        AnalysisUnitLedgerRecord {
            scan_id: "scan".into(),
            contract_version: "depgraph-analysis-unit-v2".into(),
            unit_id: "unit".into(),
            adapter: "go".into(),
            unit_root: "app".into(),
            stage: stage.into(),
            chunk_id: chunk_id.into(),
            chunk_index: Some(chunk_index),
            chunk_count: Some(chunk_count),
            status: "completed".into(),
            reused: false,
            source_paths: source_paths.iter().map(|path| (*path).into()).collect(),
            context_paths: ["app/a.go", "app/b.go"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            auxiliary_paths: Vec::new(),
            context_fingerprint: Some("context-digest".into()),
            input_fingerprint: Some("input-digest".into()),
            dependency_ids: Vec::new(),
            unknown_dependencies: false,
            error: None,
        }
    }

    #[test]
    fn refined_chunks_keep_generation_counts_but_require_every_active_slot() {
        let mut rows = vec![
            unit_row("typed", "first-child", 0, 4, &["app/a.go"]),
            unit_row("typed", "retained", 1, 2, &["app/b.go"]),
            unit_row("typed", "previous-child", 2, 3, &["app/c.go"]),
            unit_row("typed", "second-child", 3, 4, &["app/d.go"]),
        ];
        let valid = |rows: &[AnalysisUnitLedgerRecord]| {
            valid_chunks(&rows.iter().collect::<Vec<_>>(), &mut BTreeSet::new())
        };
        assert!(valid(&rows));
        rows.rotate_left(1);
        assert!(
            valid(&rows),
            "retained generation may be the first ledger row"
        );
        rows.rotate_right(1);
        for index in 0..rows.len() {
            let mut missing = rows.clone();
            missing.remove(index);
            assert!(!valid(&missing), "missing slot {index} accepted");
        }
        rows[3].chunk_index = Some(2);
        assert!(!valid(&rows), "duplicate slot accepted");
        rows[3].chunk_index = Some(3);
        rows[3].chunk_count = Some(3);
        assert!(!valid(&rows), "slot beyond its generation count accepted");
        rows[3].chunk_count = None;
        assert!(!valid(&rows), "missing generation count accepted");
    }

    #[test]
    fn v2_requires_all_syntax_chunks_and_one_semantic_context() {
        let mut syntax_a = unit_row("syntax", "a", 0, 2, &["app/a.go"]);
        let syntax_b = unit_row("syntax", "b", 1, 2, &["app/b.go"]);
        let semantic = unit_row("semantic", "semantic", 0, 1, &["app/a.go", "app/b.go"]);
        let summary = aggregate_analysis_coverage(
            "depgraph-analysis-unit-v2",
            Some("plan"),
            Some("input"),
            &[syntax_a.clone(), syntax_b.clone(), semantic.clone()],
        );
        assert!(summary.complete);
        assert_eq!(summary.completed_units, 1);
        assert_eq!(summary.semantic_complete_units, 1);

        let missing = aggregate_analysis_coverage(
            "depgraph-analysis-unit-v2",
            None,
            None,
            &[syntax_a.clone(), semantic.clone()],
        );
        assert!(!missing.complete);
        assert!(
            missing
                .reasons
                .contains(&"analysis-unit-chunk-count-mismatch".into())
        );

        syntax_a.unknown_dependencies = true;
        let unknown = aggregate_analysis_coverage(
            "depgraph-analysis-unit-v2",
            None,
            None,
            &[syntax_a, syntax_b, semantic],
        );
        assert!(!unknown.complete);
        assert!(
            unknown
                .reasons
                .contains(&"analysis-unit-unknown-dependency".into())
        );
    }

    #[test]
    fn v2_context_can_include_dependency_sources_without_claiming_their_coverage() {
        let mut syntax_a = unit_row("syntax", "a", 0, 2, &["app/a.go"]);
        let mut syntax_b = unit_row("syntax", "b", 1, 2, &["app/b.go"]);
        let typed = unit_row("typed", "typed", 0, 1, &["app/a.go", "app/b.go"]);
        let mut semantic = unit_row("semantic", "semantic", 0, 1, &["app/a.go", "app/b.go"]);
        for row in [&mut syntax_a, &mut syntax_b, &mut semantic] {
            row.context_paths.push("shared/dependency.go".into());
        }
        let rows = vec![syntax_a, syntax_b, typed, semantic];
        let complete = |rows: &[AnalysisUnitLedgerRecord]| {
            aggregate_analysis_coverage(
                "depgraph-analysis-unit-v2",
                Some("plan"),
                Some("input"),
                rows,
            )
            .complete
        };
        assert!(complete(&rows));
        let mut missing_context = rows.clone();
        missing_context[1].context_paths.pop();
        assert!(!complete(&missing_context));
        let mut lost_source = rows.clone();
        lost_source[3].source_paths.pop();
        assert!(!complete(&lost_source));
        let mut duplicate_source = rows.clone();
        duplicate_source[0].source_paths.push("app/b.go".into());
        assert!(!complete(&duplicate_source));
        let mut overclaimed_dependency = rows.clone();
        overclaimed_dependency[3]
            .source_paths
            .push("shared/dependency.go".into());
        assert!(!complete(&overclaimed_dependency));
        let mut typed_wrong_scope = rows;
        typed_wrong_scope[2]
            .context_paths
            .push("shared/dependency.go".into());
        assert!(!complete(&typed_wrong_scope));
    }

    /// A package-loader worker types the owned module as package-bounded
    /// rows.  They join when they partition the owned sources exactly and
    /// each sees the whole module as its context; an overlap, a gap, or a
    /// row typed against a narrower context does not join.
    #[test]
    fn v2_typed_rows_may_partition_the_owned_sources() {
        let syntax = unit_row("syntax", "syntax", 0, 1, &["app/a.go", "app/b.go"]);
        let typed_a = unit_row("typed", "typed-a", 0, 2, &["app/a.go"]);
        let typed_b = unit_row("typed", "typed-b", 1, 2, &["app/b.go"]);
        let semantic_a = unit_row("semantic", "bodies-a", 0, 2, &["app/a.go"]);
        let semantic_b = unit_row("semantic", "bodies-b", 1, 2, &["app/b.go"]);
        let rows = vec![syntax, typed_a, typed_b, semantic_a, semantic_b];
        let summary = |rows: &[AnalysisUnitLedgerRecord]| {
            aggregate_analysis_coverage(
                "depgraph-analysis-unit-v2",
                Some("plan"),
                Some("input"),
                rows,
            )
        };
        let joined = summary(&rows);
        assert!(joined.complete, "{:?}", joined.reasons);
        assert_eq!(joined.semantic_complete_units, 1);

        let mut overlap = rows.clone();
        overlap[1].source_paths.push("app/b.go".into());
        let overlap = summary(&overlap);
        assert!(!overlap.complete);
        assert!(
            overlap
                .reasons
                .contains(&"analysis-unit-context-scope-mismatch".into())
        );

        let mut gap = rows.clone();
        gap[2].source_paths.clear();
        assert!(!summary(&gap).complete);

        let mut narrow_context = rows.clone();
        narrow_context[1].context_paths = vec!["app/a.go".into()];
        assert!(!summary(&narrow_context).complete);

        let mut missing_row = rows;
        missing_row.remove(2);
        let missing_row = summary(&missing_row);
        assert!(!missing_row.complete);
        assert!(
            missing_row
                .reasons
                .contains(&"analysis-unit-chunk-count-mismatch".into())
        );
    }

    #[test]
    fn v2_rejects_context_mismatch_and_same_unit_contract_mixing() {
        let syntax = unit_row("syntax", "a", 0, 1, &["app/a.go", "app/b.go"]);
        let mut semantic = unit_row("semantic", "semantic", 0, 1, &["app/a.go", "app/b.go"]);
        semantic.context_fingerprint = Some("different-context".into());
        let mismatch = aggregate_analysis_coverage(
            "depgraph-analysis-unit-v2",
            None,
            None,
            &[syntax.clone(), semantic],
        );
        assert!(!mismatch.complete);
        assert!(
            mismatch
                .reasons
                .contains(&"analysis-unit-context-fingerprint-mismatch".into())
        );

        let mut legacy = syntax;
        legacy.contract_version = "depgraph-analysis-unit-v1".into();
        legacy.chunk_id.clear();
        legacy.chunk_index = None;
        legacy.chunk_count = None;
        let mixed = aggregate_analysis_coverage(
            "depgraph-analysis-unit-mixed",
            None,
            None,
            &[
                legacy,
                unit_row("semantic", "semantic", 0, 1, &["app/a.go", "app/b.go"]),
            ],
        );
        assert!(!mixed.complete);
        assert!(
            mixed
                .reasons
                .contains(&"analysis-unit-contract-mismatch".into())
        );
    }

    #[test]
    fn v2_profile_join_requires_the_durable_chunk_ledger() -> Result<()> {
        let profiles = [v2_profile("syntax"), v2_profile("semantic")];
        let rows = [
            unit_row("syntax", "syntax-a", 0, 2, &["app/a.go"]),
            unit_row("syntax", "syntax-b", 1, 2, &["app/b.go"]),
            unit_row("semantic", "semantic", 0, 1, &["app/a.go", "app/b.go"]),
        ];

        let joined = aggregate_completeness(&profiles, Some(&rows))?.unwrap();
        assert!(joined.contains("syntax-complete"));
        assert!(joined.contains("semantic-complete"));

        // v2 profiles cannot promote semantic completeness based only on
        // their stage completion payloads; the durable chunk set is required.
        let without_ledger = aggregate_completeness(&profiles, None)?.unwrap();
        assert!(without_ledger.contains("syntax-complete"));
        assert!(!without_ledger.contains("semantic-complete"));

        let mut failed_rows = rows;
        failed_rows[1].status = "failed".into();
        let failed = aggregate_completeness(&profiles, Some(&failed_rows))?.unwrap();
        assert!(!failed.contains("semantic-complete"));
        Ok(())
    }

    #[test]
    fn v2_accepts_one_empty_manifest_batch() {
        let mut syntax = unit_row("syntax", "syntax", 0, 1, &[]);
        let mut semantic = unit_row("semantic", "semantic", 0, 1, &[]);
        syntax.context_paths.clear();
        semantic.context_paths.clear();
        let summary = aggregate_analysis_coverage(
            "depgraph-analysis-unit-v2",
            Some("plan"),
            Some("input"),
            &[syntax, semantic],
        );
        assert!(summary.complete);
        assert_eq!(summary.completed_units, 1);
        assert_eq!(summary.semantic_complete_units, 1);
    }

    #[test]
    fn v2_typed_stage_requires_a_successful_typed_profile() -> Result<()> {
        let syntax = unit_row("syntax", "syntax", 0, 1, &["app/a.go", "app/b.go"]);
        let typed = unit_row("typed", "typed", 0, 1, &["app/a.go", "app/b.go"]);
        let semantic = unit_row("semantic", "semantic", 0, 1, &["app/a.go", "app/b.go"]);
        let rows = [syntax, typed, semantic];
        let summary = aggregate_analysis_coverage(
            "depgraph-analysis-unit-v2",
            Some("plan"),
            Some("input"),
            &rows,
        );
        assert!(summary.complete);

        let profiles = [
            v2_profile("syntax"),
            v2_typed_profile(true),
            v2_profile("semantic"),
        ];
        let joined = aggregate_completeness(&profiles, Some(&rows))?.unwrap();
        assert!(joined.contains("semantic-complete"));
        assert_eq!(semantic_complete_units(&profiles, Some(&rows)), 1);

        let incomplete_typed = [
            v2_profile("syntax"),
            v2_typed_profile(false),
            v2_profile("semantic"),
        ];
        let incomplete = aggregate_completeness(&incomplete_typed, Some(&rows))?.unwrap();
        assert!(!incomplete.contains("semantic-complete"));
        assert_eq!(semantic_complete_units(&incomplete_typed, Some(&rows)), 0);

        let mut missing_typed = rows.to_vec();
        missing_typed[1].status = "queued".to_owned();
        let missing =
            aggregate_analysis_coverage("depgraph-analysis-unit-v2", None, None, &missing_typed);
        assert!(!missing.complete);
        assert!(
            missing
                .reasons
                .contains(&"analysis-unit-unanalysed".to_owned())
        );
        Ok(())
    }

    #[test]
    fn v2_multiple_base_profiles_join_each_axis_and_count_the_unit_once() -> Result<()> {
        let rows = [
            unit_row("syntax", "syntax", 0, 1, &["app/a.go", "app/b.go"]),
            unit_row("typed", "typed", 0, 1, &["app/a.go", "app/b.go"]),
            unit_row("semantic", "semantic", 0, 1, &["app/a.go", "app/b.go"]),
        ];
        let profiles_for = |base: &str| {
            let mut syntax = v2_profile("syntax");
            let mut typed = v2_typed_profile(true);
            let mut semantic = v2_profile("semantic");
            for (profile, stage) in [
                (&mut syntax, "syntax"),
                (&mut typed, "typed"),
                (&mut semantic, "semantic"),
            ] {
                profile.id = format!("profile:{base}:{stage}");
                profile.properties["analysis_base_profile_id"] = json!(base);
                profile.features = vec![base.to_owned()];
            }
            vec![syntax, typed, semantic]
        };
        let mut profiles = profiles_for("go:base-a");
        profiles.extend(profiles_for("go:base-b"));
        let joined = aggregate_completeness(&profiles, Some(&rows))?.unwrap();
        assert!(joined.contains("semantic-complete"));
        assert_eq!(semantic_complete_units(&profiles, Some(&rows)), 1);

        let mut incomplete = profiles_for("go:base-a");
        let mut base_b = profiles_for("go:base-b");
        base_b[2]
            .coverage
            .as_mut()
            .unwrap()
            .completeness
            .retain(|level| level != "semantic-complete");
        incomplete.extend(base_b);
        let joined = aggregate_completeness(&incomplete, Some(&rows))?.unwrap();
        assert!(!joined.contains("semantic-complete"));
        assert_eq!(semantic_complete_units(&incomplete, Some(&rows)), 0);
        Ok(())
    }

    #[test]
    fn v2_go_joins_dependency_snapshot_base_ids_using_configuration_axes() -> Result<()> {
        let rows = [
            unit_row("syntax", "syntax", 0, 1, &["app/a.go", "app/b.go"]),
            unit_row("typed", "typed", 0, 1, &["app/a.go", "app/b.go"]),
            unit_row("semantic", "semantic", 0, 1, &["app/a.go", "app/b.go"]),
        ];
        let mut profiles = vec![
            v2_profile("syntax"),
            v2_typed_profile(true),
            v2_profile("semantic"),
        ];
        profiles[0].properties["analysis_base_profile_id"] = json!("syntax-without-snapshot");
        for profile in &mut profiles[1..] {
            profile.properties["analysis_base_profile_id"] = json!("typed-dependency-snapshot");
        }
        assert!(
            aggregate_completeness(&profiles, Some(&rows))?
                .unwrap()
                .contains("semantic-complete")
        );
        assert_eq!(semantic_complete_units(&profiles, Some(&rows)), 1);

        // Both typed stages load the dependency snapshot; only syntax may
        // lack it. A different typed/SSA snapshot must remain incomplete.
        let mut changed_dependency = profiles.clone();
        changed_dependency[2].properties["analysis_base_profile_id"] = json!("changed-dependency");
        assert!(
            !aggregate_completeness(&changed_dependency, Some(&rows))?
                .unwrap()
                .contains("semantic-complete")
        );
        assert_eq!(semantic_complete_units(&changed_dependency, Some(&rows)), 0);

        // Equal axes cannot hide an extra or conflicting stage behind a new
        // base ID; every configuration still needs exactly one stage set.
        let mut duplicate = profiles[0].clone();
        duplicate.id = "profile:duplicate".into();
        duplicate.properties["analysis_base_profile_id"] = json!("other-syntax-base");
        profiles.push(duplicate);
        assert!(
            !aggregate_completeness(&profiles, Some(&rows))?
                .unwrap()
                .contains("semantic-complete")
        );
        assert_eq!(semantic_complete_units(&profiles, Some(&rows)), 0);
        Ok(())
    }

    #[test]
    fn only_complete_matching_stages_establish_aggregate_semantics() -> Result<()> {
        let syntax = profile("syntax");
        let semantic_profile = profile("semantic");
        assert!(semantic(&[syntax.clone(), semantic_profile.clone()])?);
        assert!(!semantic(std::slice::from_ref(&syntax))?);
        assert!(!semantic(std::slice::from_ref(&semantic_profile))?);
        assert!(!semantic(&[
            syntax.clone(),
            syntax.clone(),
            semantic_profile.clone()
        ])?);
        assert_eq!(
            syntax.coverage.as_ref().unwrap().completeness,
            ["syntax-complete"]
        );
        for field in [
            "analysis_unit_id",
            "analysis_unit_root",
            "profile_selection_plan_id",
        ] {
            let mut incompatible = semantic_profile.clone();
            incompatible.properties[field] = json!("different");
            assert!(!semantic(&[syntax.clone(), incompatible])?, "{field}");
        }
        let mut incompatible = semantic_profile.clone();
        incompatible.target = Some("different".into());
        assert!(!semantic(&[syntax.clone(), incompatible])?);
        let mut incomplete = syntax.clone();
        incomplete.coverage.as_mut().unwrap().completeness.clear();
        assert!(!semantic(&[incomplete, semantic_profile.clone()])?);
        let mut legacy = syntax.clone();
        legacy.properties = json!({});
        assert!(!semantic(&[syntax, semantic_profile, legacy])?);
        Ok(())
    }
}
