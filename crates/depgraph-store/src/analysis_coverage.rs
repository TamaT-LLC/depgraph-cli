//! Reconstruct aggregate completeness without changing individual profiles.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

use crate::ProfileRecord;

pub(crate) fn aggregate_completeness(
    profiles: &[ProfileRecord],
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
    let mut units = BTreeMap::<(&str, &str), Vec<(usize, &str)>>::new();
    for (index, profile) in profiles.iter().enumerate() {
        if profile.properties["analysis_unit_contract"] != "depgraph-analysis-unit-v1" {
            continue;
        }
        if profile.language != "go" {
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
        if !matches!(stage, "syntax" | "semantic") {
            bail!("analysis-unit profile {} has an unknown stage", profile.id);
        }
        units.entry((unit, root)).or_default().push((index, stage));
    }
    for stages in units.values() {
        // An unmatched, duplicated, or incompatible stage cannot establish
        // aggregate semantic completeness, even if one profile claims it.
        let syntax = stages.iter().find(|(_, stage)| *stage == "syntax");
        let semantic = stages.iter().find(|(_, stage)| *stage == "semantic");
        let joined = match (syntax, semantic) {
            (Some((syntax, _)), Some((semantic, _))) if stages.len() == 2 => {
                levels[*syntax].contains("syntax-complete")
                    && levels[*semantic].contains("semantic-complete")
                    && same_axes(&profiles[*syntax], &profiles[*semantic])
            }
            _ => false,
        };
        for (index, _) in stages {
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

fn same_axes(left: &ProfileRecord, right: &ProfileRecord) -> bool {
    left.language == right.language
        && left.toolchain == right.toolchain
        && left.command == right.command
        && left.target == right.target
        && left.features == right.features
        && left.environment == right.environment
        && left.source_revision == right.source_revision
        && [
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
        .all(|key| left.properties[key] == right.properties[key])
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

    fn semantic(profiles: &[ProfileRecord]) -> Result<bool> {
        Ok(aggregate_completeness(profiles)?
            .is_some_and(|levels| levels.contains("semantic-complete")))
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
