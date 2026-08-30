use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use anyhow::{Context, Result, bail};
use depgraph_protocol::EvidenceKind;
use depgraph_store::{
    EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, ProfileRecord, diff_graph_snapshots,
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    policy::{
        AppliedPolicySuppression, PolicyCondition, PolicyConfig, PolicyEntity,
        PolicyEvidenceRequirement, PolicyEvidenceSpan, PolicyMatchKind, PolicyPathStep,
        PolicyPattern, PolicyProfileFilter, PolicyResult, PolicyRule, PolicyRuleKind,
        PolicySelector, PolicySelectorCardinality, PolicySelectorField, PolicySelectorKind,
        PolicySuppression, PolicyViolation, PublicApiChange, PublicApiChangeKind,
    },
    query::{CycleLevel, cycles},
};

#[derive(Debug, thiserror::Error)]
#[error("policy evaluation exhausted its bounded work budget")]
pub(crate) struct PolicyEvaluationWorkExhausted;

#[derive(Debug, thiserror::Error)]
#[error("policy evaluation was cancelled")]
pub(crate) struct PolicyEvaluationCancelled;

pub(crate) fn is_policy_evaluation_resource_exhausted(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<PolicyEvaluationWorkExhausted>()
        .is_some()
}

pub(crate) fn is_policy_evaluation_cancelled(error: &anyhow::Error) -> bool {
    error.downcast_ref::<PolicyEvaluationCancelled>().is_some()
}

struct PolicyEvaluationWork {
    used: usize,
    maximum: usize,
}

impl PolicyEvaluationWork {
    const fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    fn step(&mut self, is_cancelled: &mut impl FnMut() -> bool) -> Result<()> {
        if is_cancelled() {
            return Err(PolicyEvaluationCancelled.into());
        }
        if self.used >= self.maximum {
            return Err(PolicyEvaluationWorkExhausted.into());
        }
        self.used += 1;
        Ok(())
    }

    fn steps(&mut self, count: usize, is_cancelled: &mut impl FnMut() -> bool) -> Result<()> {
        for _ in 0..count {
            self.step(is_cancelled)?;
        }
        Ok(())
    }
}

fn charge_sort_work(
    len: usize,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    if len <= 1 {
        return Ok(());
    }
    let comparison_rounds = usize::BITS as usize - (len - 1).leading_zeros() as usize;
    work.steps(len.saturating_mul(comparison_rounds), is_cancelled)
}

fn charge_ordered_collection_work(
    len: usize,
    key_units: usize,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    let comparison_rounds = if len == 0 {
        1
    } else {
        usize::BITS as usize - len.leading_zeros() as usize
    };
    work.steps(
        comparison_rounds.saturating_mul(key_units.max(1)),
        is_cancelled,
    )
}

fn charge_json_value_work(
    value: &Value,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        work.step(is_cancelled)?;
        match value {
            Value::Array(values) => {
                for value in values {
                    work.step(is_cancelled)?;
                    pending.push(value);
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    work.step(is_cancelled)?;
                    pending.push(value);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BoundaryViolationComparisonKey {
    rule_id: String,
    source_id: String,
    target_id: String,
    profile_id: Option<String>,
    dependency_node_path: Vec<(String, String)>,
}

/// Return current evaluator IDs representing boundary-violation occurrences
/// whose semantic-path multiplicity increased from the before result.
///
/// `PolicyViolation.id` deliberately authenticates exact edge IDs. Worker
/// edge IDs can change when a dependency site moves without changing the
/// policy-relevant node path, so using the raw ID as the comparison key would
/// report a continuing violation as new. The emitted value remains a stable
/// current evaluator ID; only before/after correspondence ignores edge
/// identity and evidence position. If all raw IDs in one semantic group move
/// while a parallel occurrence is also added, the policy results contain no
/// provenance that can identify the physical added site. In that case the
/// lexicographically selected surplus ID is a deterministic after-side
/// representative, not a claim of source-occurrence correspondence.
#[must_use]
#[cfg(test)]
pub(crate) fn new_boundary_violation_ids(
    before: &PolicyResult,
    after: &PolicyResult,
    config: &PolicyConfig,
) -> BTreeSet<String> {
    let mut work = PolicyEvaluationWork::new(usize::MAX);
    new_boundary_violation_ids_bounded(before, after, config, &mut work, &mut || false)
        .expect("unbounded, non-cancellable boundary comparison cannot fail")
}

fn new_boundary_violation_ids_bounded(
    before: &PolicyResult,
    after: &PolicyResult,
    config: &PolicyConfig,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeSet<String>> {
    let mut boundary_rule_ids = BTreeSet::new();
    for rule in &config.rules {
        work.step(is_cancelled)?;
        if matches!(
            rule.kind,
            PolicyRuleKind::LayerBoundary
                | PolicyRuleKind::ForbiddenDependency
                | PolicyRuleKind::RuntimeBoundary
        ) {
            charge_ordered_collection_work(boundary_rule_ids.len(), 1, work, is_cancelled)?;
            boundary_rule_ids.insert(rule.id.as_str());
        }
    }

    let mut before_by_key = BTreeMap::<BoundaryViolationComparisonKey, Vec<String>>::new();
    for violation in &before.violations {
        work.step(is_cancelled)?;
        if violation.suppression.is_some()
            || !boundary_rule_ids.contains(violation.rule_id.as_str())
        {
            continue;
        }
        let key = boundary_violation_comparison_key_bounded(violation, work, is_cancelled)?;
        charge_ordered_collection_work(
            before_by_key.len(),
            key.dependency_node_path.len().saturating_add(4),
            work,
            is_cancelled,
        )?;
        before_by_key
            .entry(key)
            .or_default()
            .push(violation.id.clone());
    }
    let mut after_by_key = BTreeMap::<BoundaryViolationComparisonKey, Vec<String>>::new();
    for violation in &after.violations {
        work.step(is_cancelled)?;
        if violation.suppression.is_some()
            || !boundary_rule_ids.contains(violation.rule_id.as_str())
        {
            continue;
        }
        let key = boundary_violation_comparison_key_bounded(violation, work, is_cancelled)?;
        charge_ordered_collection_work(
            after_by_key.len(),
            key.dependency_node_path.len().saturating_add(4),
            work,
            is_cancelled,
        )?;
        after_by_key
            .entry(key)
            .or_default()
            .push(violation.id.clone());
    }
    let mut new_ids = BTreeSet::new();
    for (key, mut ids) in after_by_key {
        work.step(is_cancelled)?;
        charge_sort_work(ids.len(), work, is_cancelled)?;
        ids.sort();
        let mut before_id_counts = BTreeMap::<String, usize>::new();
        let mut remaining_before = 0usize;
        charge_ordered_collection_work(
            before_by_key.len(),
            key.dependency_node_path.len().saturating_add(4),
            work,
            is_cancelled,
        )?;
        for id in before_by_key.remove(&key).unwrap_or_default() {
            work.step(is_cancelled)?;
            charge_ordered_collection_work(before_id_counts.len(), 1, work, is_cancelled)?;
            let count = before_id_counts.entry(id).or_default();
            *count = count.saturating_add(1);
            remaining_before = remaining_before.saturating_add(1);
        }

        // Preserve exact evaluator identities first. This keeps a continuing
        // parallel edge paired with itself, so the ID emitted for an added
        // occurrence is the added edge's ID rather than an arbitrary sibling.
        let mut unmatched_after = Vec::new();
        for id in ids {
            work.step(is_cancelled)?;
            let Some(count) = before_id_counts.get_mut(&id) else {
                unmatched_after.push(id);
                continue;
            };
            if *count == 0 {
                unmatched_after.push(id);
                continue;
            }
            *count -= 1;
            remaining_before = remaining_before.saturating_sub(1);
        }

        // Any remaining before occurrence changed only its position-derived
        // edge identity. Pair those semantically before classifying surplus
        // after IDs as deterministic representatives of the increased
        // multiplicity. PolicyResult intentionally carries no line-movement
        // provenance, so selecting a physical added site here would be a
        // guess when every parallel occurrence changed its raw ID.
        let moved_continuing = remaining_before.min(unmatched_after.len());
        for id in unmatched_after.into_iter().skip(moved_continuing) {
            work.step(is_cancelled)?;
            charge_ordered_collection_work(new_ids.len(), 1, work, is_cancelled)?;
            new_ids.insert(id);
        }
    }
    Ok(new_ids)
}

fn boundary_violation_comparison_key_bounded(
    violation: &PolicyViolation,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BoundaryViolationComparisonKey> {
    work.step(is_cancelled)?;
    let mut dependency_node_path = Vec::with_capacity(violation.dependency_path.len());
    for step in &violation.dependency_path {
        work.step(is_cancelled)?;
        dependency_node_path.push((step.source_id.clone(), step.target_id.clone()));
    }
    Ok(BoundaryViolationComparisonKey {
        rule_id: violation.rule_id.clone(),
        source_id: violation.source.id.clone(),
        target_id: violation.target.id.clone(),
        profile_id: violation.profile_id.clone(),
        dependency_node_path,
    })
}

/// Evaluate the architecture policy against one validated graph snapshot.
///
/// Selector cardinality is resolved before any rule is evaluated. Every rule then
/// operates on the same admitted edge contract: profile, condition, precision,
/// resolution status, and source evidence must all match.
pub fn evaluate_policy(
    snapshot_id: impl Into<String>,
    snapshot: &GraphSnapshot,
    config: &PolicyConfig,
) -> Result<PolicyResult> {
    evaluate_policy_cancellable(snapshot_id, snapshot, config, usize::MAX, || false)
}

/// Evaluate a policy while bounding the potentially quadratic RuntimeBoundary
/// selector traversal and observing cooperative cancellation.
pub(crate) fn evaluate_policy_cancellable(
    snapshot_id: impl Into<String>,
    snapshot: &GraphSnapshot,
    config: &PolicyConfig,
    maximum_work: usize,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<PolicyResult> {
    let mut work = PolicyEvaluationWork::new(maximum_work);
    evaluate_policy_with_work(snapshot_id, snapshot, config, &mut work, &mut is_cancelled)
}

fn evaluate_policy_with_work(
    snapshot_id: impl Into<String>,
    snapshot: &GraphSnapshot,
    config: &PolicyConfig,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyResult> {
    work.step(is_cancelled)?;
    work.steps(
        config.rules.len().saturating_add(config.suppressions.len()),
        is_cancelled,
    )?;
    config.validate()?;
    let mut nodes = BTreeMap::new();
    for node in &snapshot.nodes {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(nodes.len(), 1, work, is_cancelled)?;
        nodes.insert(node.id.as_str(), node);
    }
    let mut violations = BTreeMap::new();

    for rule in &config.rules {
        work.step(is_cancelled)?;
        // These rule kinds use specialized evaluation contexts outside this static
        // architecture pass. Their dedicated evaluators compose with this pass, so
        // do not let them discard otherwise valid static architecture violations.
        if rule.kind == PolicyRuleKind::PublicApiChange {
            continue;
        }
        let suppressions =
            resolve_suppressions_bounded(snapshot, config, Some(&rule.id), work, is_cancelled)?;
        let sources = resolve_selector_bounded(
            snapshot,
            &rule.source,
            &format!("rule {:?} source", rule.id),
            work,
            is_cancelled,
        )?;
        let targets = resolve_selector_bounded(
            snapshot,
            &rule.target,
            &format!("rule {:?} target", rule.id),
            work,
            is_cancelled,
        )?;
        let source_ids = borrowed_node_id_set_bounded(&sources, work, is_cancelled)?;
        let target_ids = borrowed_node_id_set_bounded(&targets, work, is_cancelled)?;
        let admitted = if rule.kind == PolicyRuleKind::RuntimeBoundary {
            Vec::new()
        } else {
            admitted_edges_with_options_bounded(snapshot, rule, true, true, work, is_cancelled)?
        };

        let evaluated = match rule.kind {
            PolicyRuleKind::LayerBoundary | PolicyRuleKind::ForbiddenDependency => {
                evaluate_direct_bounded(
                    rule,
                    &admitted,
                    &source_ids,
                    &target_ids,
                    &nodes,
                    &suppressions,
                    work,
                    is_cancelled,
                )?
            }
            PolicyRuleKind::Cycle => evaluate_cycles(
                snapshot,
                rule,
                &admitted,
                &source_ids,
                &target_ids,
                &nodes,
                &suppressions,
            )?,
            PolicyRuleKind::DependencyDepth => {
                evaluate_depth(rule, &admitted, &sources, &targets, &nodes, &suppressions)?
            }
            PolicyRuleKind::FanIn => evaluate_fan_in(
                rule,
                &admitted,
                &source_ids,
                &targets,
                &nodes,
                &suppressions,
            )?,
            PolicyRuleKind::FanOut => evaluate_fan_out(
                rule,
                &admitted,
                &sources,
                &target_ids,
                &nodes,
                &suppressions,
            )?,
            PolicyRuleKind::RuntimeBoundary => evaluate_runtime_boundary(
                rule,
                snapshot,
                &sources,
                &target_ids,
                &nodes,
                &suppressions,
                work,
                is_cancelled,
            )?,
            PolicyRuleKind::PublicApiChange => {
                unreachable!("public API rules are handled by the snapshot-diff evaluator")
            }
        };
        for violation in evaluated {
            work.step(is_cancelled)?;
            charge_ordered_collection_work(violations.len(), 1, work, is_cancelled)?;
            violations.entry(violation.id.clone()).or_insert(violation);
        }
    }

    let mut ordered = Vec::with_capacity(violations.len());
    for violation in violations.into_values() {
        work.step(is_cancelled)?;
        work.steps(
            violation
                .dependency_path
                .len()
                .saturating_add(violation.evidence.len()),
            is_cancelled,
        )?;
        ordered.push(violation);
    }
    charge_sort_work(ordered.len(), work, is_cancelled)?;
    let result = PolicyResult::new(snapshot_id, ordered);
    work.steps(result.violations.len(), is_cancelled)?;
    result.validate()?;
    Ok(result)
}

/// Evaluate snapshot-local rules against `to` and public API change rules
/// against the deterministic diff from `from` to `to`.
pub fn evaluate_policy_diff(
    from_snapshot_id: &str,
    from: &GraphSnapshot,
    to_snapshot_id: &str,
    to: &GraphSnapshot,
    config: &PolicyConfig,
) -> Result<PolicyResult> {
    evaluate_policy_diff_cancellable(
        from_snapshot_id,
        from,
        to_snapshot_id,
        to,
        config,
        usize::MAX,
        || false,
    )
}

/// Evaluate a snapshot diff with the same bounded RuntimeBoundary evaluator
/// used by the graph service.
pub(crate) fn evaluate_policy_diff_cancellable(
    from_snapshot_id: &str,
    from: &GraphSnapshot,
    to_snapshot_id: &str,
    to: &GraphSnapshot,
    config: &PolicyConfig,
    maximum_work: usize,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<PolicyResult> {
    let mut work = PolicyEvaluationWork::new(maximum_work);
    evaluate_policy_diff_with_work(
        from_snapshot_id,
        from,
        to_snapshot_id,
        to,
        config,
        &mut work,
        &mut is_cancelled,
    )
}

/// Evaluate both sides of a health-audit policy comparison under one shared
/// work budget.  RuntimeBoundary evaluation is performed twice (once for each
/// pinned snapshot), so giving each side an independent ceiling would double
/// the service's intended bound.
pub(crate) fn evaluate_boundary_violation_ids_cancellable(
    before_snapshot_id: &str,
    before: &GraphSnapshot,
    after_snapshot_id: &str,
    after: &GraphSnapshot,
    config: &PolicyConfig,
    maximum_work: usize,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<BTreeSet<String>> {
    let mut work = PolicyEvaluationWork::new(maximum_work);
    let boundary_config = boundary_policy_config_bounded(config, &mut work, &mut is_cancelled)?;
    if boundary_config.rules.is_empty() {
        return Ok(BTreeSet::new());
    }
    let before_result = evaluate_policy_with_work(
        before_snapshot_id,
        before,
        &boundary_config,
        &mut work,
        &mut is_cancelled,
    )?;
    let after_result = evaluate_policy_diff_with_work(
        before_snapshot_id,
        before,
        after_snapshot_id,
        after,
        &boundary_config,
        &mut work,
        &mut is_cancelled,
    )?;
    new_boundary_violation_ids_bounded(
        &before_result,
        &after_result,
        &boundary_config,
        &mut work,
        &mut is_cancelled,
    )
}

fn boundary_policy_config_bounded(
    config: &PolicyConfig,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyConfig> {
    work.step(is_cancelled)?;
    work.steps(
        config.rules.len().saturating_add(config.suppressions.len()),
        is_cancelled,
    )?;
    config.validate()?;

    let mut rules = Vec::new();
    let mut rule_ids = BTreeSet::new();
    for rule in &config.rules {
        work.step(is_cancelled)?;
        if matches!(
            rule.kind,
            PolicyRuleKind::LayerBoundary
                | PolicyRuleKind::ForbiddenDependency
                | PolicyRuleKind::RuntimeBoundary
        ) {
            charge_ordered_collection_work(rule_ids.len(), 1, work, is_cancelled)?;
            rule_ids.insert(rule.id.as_str());
            rules.push(rule.clone());
        }
    }
    let mut suppressions = Vec::new();
    for suppression in &config.suppressions {
        work.step(is_cancelled)?;
        if rule_ids.contains(suppression.rule_id.as_str()) {
            suppressions.push(suppression.clone());
        }
    }
    let filtered = PolicyConfig {
        schema_version: config.schema_version.clone(),
        rules,
        suppressions,
    };
    filtered.validate()?;
    Ok(filtered)
}

fn evaluate_policy_diff_with_work(
    from_snapshot_id: &str,
    from: &GraphSnapshot,
    to_snapshot_id: &str,
    to: &GraphSnapshot,
    config: &PolicyConfig,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyResult> {
    config.validate()?;
    let current = evaluate_policy_with_work(to_snapshot_id, to, config, work, is_cancelled)?;
    if !config
        .rules
        .iter()
        .any(|rule| rule.kind == PolicyRuleKind::PublicApiChange)
    {
        return Ok(current);
    }
    let diff = diff_graph_snapshots(from_snapshot_id, to_snapshot_id, from.clone(), to.clone())?;
    let rename_pairs: Vec<_> = diff
        .renames
        .iter()
        .map(|rename| (rename.old_id.as_str(), rename.new_id.as_str()))
        .collect();
    let mut violations: BTreeMap<_, _> = current
        .violations
        .into_iter()
        .map(|violation| (violation.id.clone(), violation))
        .collect();
    let mut api_changes = Vec::new();
    let from_node_evidence = NodeEvidenceIndex::new(from);
    let to_node_evidence = NodeEvidenceIndex::new(to);

    for rule in config
        .rules
        .iter()
        .filter(|rule| rule.kind == PolicyRuleKind::PublicApiChange)
    {
        validate_diff_selector(from, to, &rule.target, &rule.id)?;
        let suppressions = resolve_diff_suppressions(from, to, &rename_pairs, config, &rule.id)?;
        let admitted = admitted_edges_with_options(from, rule, false, false)?;
        let mut rule_changes = Vec::new();

        for node in &diff.nodes.added {
            if let Some(change) = classify_public_api_change(
                rule,
                PublicApiChangeKind::Added,
                None,
                Some(node),
                Vec::new(),
                from,
                to,
                &from_node_evidence,
                &to_node_evidence,
            )? {
                rule_changes.push((change, None));
            }
        }
        for node in &diff.nodes.removed {
            if let Some(change) = classify_public_api_change(
                rule,
                PublicApiChangeKind::Removed,
                Some(node),
                None,
                Vec::new(),
                from,
                to,
                &from_node_evidence,
                &to_node_evidence,
            )? {
                rule_changes.push((change, Some(node)));
            }
        }
        for changed in &diff.nodes.changed {
            if let Some(change) = classify_public_api_change(
                rule,
                PublicApiChangeKind::Changed,
                Some(&changed.before),
                Some(&changed.after),
                changed.changed_fields.clone(),
                from,
                to,
                &from_node_evidence,
                &to_node_evidence,
            )? {
                rule_changes.push((change, Some(&changed.before)));
            }
        }
        for rename in &diff.renames {
            if let Some(change) = classify_public_api_change(
                rule,
                PublicApiChangeKind::Changed,
                Some(&rename.before),
                Some(&rename.after),
                rename.changed_fields.clone(),
                from,
                to,
                &from_node_evidence,
                &to_node_evidence,
            )? {
                rule_changes.push((change, Some(&rename.before)));
            }
        }

        let needs_impact = rule_changes.iter().any(|(change, _)| change.breaking);
        let sources = needs_impact
            .then(|| {
                resolve_selector(
                    from,
                    &rule.source,
                    &format!("public API rule {:?} source", rule.id),
                )
            })
            .transpose()?
            .unwrap_or_default();
        let nodes: BTreeMap<_, _> = from
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect();

        for (change, before) in rule_changes {
            if let Some(before) = before {
                for violation in evaluate_public_api_impact(
                    rule,
                    &change,
                    before,
                    &sources,
                    &admitted,
                    &nodes,
                    &suppressions,
                    from,
                    to,
                )? {
                    violations.entry(violation.id.clone()).or_insert(violation);
                }
            }
            api_changes.push(change);
        }
    }

    let result = PolicyResult::with_api_changes(
        to_snapshot_id,
        api_changes,
        violations.into_values().collect(),
    );
    result.validate()?;
    Ok(result)
}

fn validate_diff_selector(
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    selector: &PolicySelector,
    rule_id: &str,
) -> Result<()> {
    if selector.cardinality != PolicySelectorCardinality::One {
        return Ok(());
    }
    let before = from
        .nodes
        .iter()
        .filter(|node| selector_matches_node(node, selector))
        .count();
    let after = to
        .nodes
        .iter()
        .filter(|node| selector_matches_node(node, selector))
        .count();
    if before > 1 || after > 1 || (before == 0 && after == 0) {
        bail!(
            "public API rule {rule_id:?} target selector must resolve to exactly one node in at least one snapshot and at most one per snapshot, but matched {before} before and {after} after"
        );
    }
    Ok(())
}

fn resolve_diff_suppressions<'a>(
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    rename_pairs: &[(&str, &str)],
    config: &'a PolicyConfig,
    rule_id: &str,
) -> Result<Vec<ResolvedSuppression<'a>>> {
    let mut resolved = Vec::new();
    for suppression in config
        .suppressions
        .iter()
        .filter(|suppression| suppression.rule_id == rule_id)
    {
        let source_ids = suppression
            .scope
            .source
            .as_ref()
            .map(|selector| {
                resolve_diff_scope_selector(
                    from,
                    to,
                    rename_pairs,
                    selector,
                    &format!("suppression {:?} source", suppression.id),
                )
            })
            .transpose()?;
        let target_ids = suppression
            .scope
            .target
            .as_ref()
            .map(|selector| {
                resolve_diff_scope_selector(
                    from,
                    to,
                    rename_pairs,
                    selector,
                    &format!("suppression {:?} target", suppression.id),
                )
            })
            .transpose()?;
        resolved.push(ResolvedSuppression {
            suppression,
            source_ids,
            target_ids,
        });
    }
    resolved.sort_by(|left, right| left.suppression.id.cmp(&right.suppression.id));
    Ok(resolved)
}

fn resolve_diff_scope_selector(
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    rename_pairs: &[(&str, &str)],
    selector: &PolicySelector,
    description: &str,
) -> Result<BTreeSet<String>> {
    let before: Vec<_> = from
        .nodes
        .iter()
        .filter(|node| selector_matches_node(node, selector))
        .collect();
    let after: Vec<_> = to
        .nodes
        .iter()
        .filter(|node| selector_matches_node(node, selector))
        .collect();
    if selector.cardinality == PolicySelectorCardinality::One
        && (before.len() > 1 || after.len() > 1 || (before.is_empty() && after.is_empty()))
    {
        bail!(
            "policy selector {description} must resolve to at most one node per snapshot and at least one across the diff, but matched {} before and {} after",
            before.len(),
            after.len()
        );
    }
    let mut ids: BTreeSet<_> = before
        .into_iter()
        .chain(after)
        .map(|node| node.id.clone())
        .collect();
    for (old_id, new_id) in rename_pairs {
        if ids.contains(*old_id) || ids.contains(*new_id) {
            ids.insert((*old_id).to_owned());
            ids.insert((*new_id).to_owned());
        }
    }
    Ok(ids)
}

#[allow(clippy::too_many_arguments)]
fn classify_public_api_change(
    rule: &PolicyRule,
    kind: PublicApiChangeKind,
    before: Option<&NodeRecord>,
    after: Option<&NodeRecord>,
    mut changed_fields: Vec<String>,
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    from_node_evidence: &NodeEvidenceIndex<'_>,
    to_node_evidence: &NodeEvidenceIndex<'_>,
) -> Result<Option<PublicApiChange>> {
    if !before.is_some_and(|node| selector_matches_node(node, &rule.target))
        && !after.is_some_and(|node| selector_matches_node(node, &rule.target))
    {
        return Ok(None);
    }
    changed_fields.sort();
    changed_fields.dedup();
    let node = after.or(before).context("public API change has no node")?;
    let profile_id = node_profile_id(node).map(ToOwned::to_owned);
    if !optional_profile_matches(&rule.profiles, profile_id.as_deref()) {
        return Ok(None);
    }
    let profiles = if after.is_some() {
        &to.profiles
    } else {
        &from.profiles
    };
    let profile = profile_id
        .as_deref()
        .and_then(|profile_id| profiles.iter().find(|profile| profile.id == profile_id));
    let context = public_api_change_context(before, after, profile, kind, &changed_fields);
    if evaluate_condition(&rule.condition, &context) != Some(true) {
        return Ok(None);
    }

    let mut evidence = Vec::new();
    if let Some(after) = after {
        append_unique_evidence(
            &mut evidence,
            node_policy_evidence(to_node_evidence, after, &rule.evidence)?,
        );
    }
    if let Some(before) = before {
        append_unique_evidence(
            &mut evidence,
            node_policy_evidence(from_node_evidence, before, &rule.evidence)?,
        );
    }
    if evidence.len() < usize::try_from(rule.evidence.minimum_spans)? {
        return Ok(None);
    }
    let condition = canonical_condition(&PolicyCondition::All {
        conditions: vec![
            rule.condition.clone(),
            PolicyCondition::Eq {
                key: "change.kind".to_owned(),
                value: Value::String(public_api_change_kind_name(kind).to_owned()),
            },
            PolicyCondition::Eq {
                key: "change.breaking".to_owned(),
                value: Value::Bool(kind != PublicApiChangeKind::Added),
            },
        ],
    })?;
    let before_entity = before.map(|node| policy_entity(node, rule.target.kind));
    let after_entity = after.map(|node| policy_entity(node, rule.target.kind));
    let id = PublicApiChange::stable_id(
        &rule.id,
        kind,
        before_entity.as_ref().map(|entity| entity.id.as_str()),
        after_entity.as_ref().map(|entity| entity.id.as_str()),
        profile_id.as_deref(),
        &changed_fields,
    );
    Ok(Some(PublicApiChange {
        id,
        rule_id: rule.id.clone(),
        kind,
        breaking: kind != PublicApiChangeKind::Added,
        changed_fields,
        before: before_entity,
        after: after_entity,
        profile_id,
        condition,
        evidence,
    }))
}

#[allow(clippy::too_many_arguments)]
fn evaluate_public_api_impact(
    rule: &PolicyRule,
    change: &PublicApiChange,
    before: &NodeRecord,
    sources: &[&NodeRecord],
    admitted: &[AdmittedEdge<'_>],
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
    from: &GraphSnapshot,
    to: &GraphSnapshot,
) -> Result<Vec<PolicyViolation>> {
    let baseline_profile_id = node_profile_id(before);
    let mut by_profile: BTreeMap<&str, Vec<&AdmittedEdge<'_>>> = BTreeMap::new();
    for item in admitted {
        if baseline_profile_id.is_none_or(|profile_id| item.edge.profile_id == profile_id) {
            by_profile
                .entry(item.edge.profile_id.as_str())
                .or_default()
                .push(item);
        }
    }
    let mut output = BTreeMap::new();
    for (profile_id, edges) in by_profile {
        let adjacency = adjacency(&edges);
        for source in sources {
            let mut visited = BTreeSet::from([source.id.clone()]);
            let mut predecessor: HashMap<String, &AdmittedEdge<'_>> = HashMap::new();
            let mut queue = VecDeque::from([source.id.clone()]);
            while let Some(current) = queue.pop_front() {
                for item in adjacency.get(current.as_str()).into_iter().flatten() {
                    if visited.insert(item.edge.target.clone()) {
                        predecessor.insert(item.edge.target.clone(), item);
                        queue.push_back(item.edge.target.clone());
                    }
                }
            }
            if !visited.contains(&before.id) {
                continue;
            }
            let path_edges = reconstruct_path(&source.id, &before.id, &predecessor)?;
            if path_edges.is_empty() {
                continue;
            }
            let violation = make_public_api_violation(
                rule,
                change,
                source,
                before,
                Some(profile_id),
                path_edges,
                nodes,
                suppressions,
                from,
                to,
            )?;
            output.entry(violation.id.clone()).or_insert(violation);
        }
    }
    for source in sources.iter().filter(|source| source.id == before.id) {
        let violation = make_public_api_violation(
            rule,
            change,
            source,
            before,
            baseline_profile_id,
            Vec::new(),
            nodes,
            suppressions,
            from,
            to,
        )?;
        output.entry(violation.id.clone()).or_insert(violation);
    }
    Ok(output.into_values().collect())
}

#[allow(clippy::too_many_arguments)]
fn make_public_api_violation(
    rule: &PolicyRule,
    change: &PublicApiChange,
    source: &NodeRecord,
    target: &NodeRecord,
    profile_id: Option<&str>,
    path_edges: Vec<&AdmittedEdge<'_>>,
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
    from: &GraphSnapshot,
    to: &GraphSnapshot,
) -> Result<PolicyViolation> {
    if !nodes.contains_key(source.id.as_str()) || !nodes.contains_key(target.id.as_str()) {
        bail!("public API impact path references a node missing from the baseline snapshot");
    }
    let dependency_path = if path_edges.is_empty() {
        vec![PolicyPathStep {
            source_id: source.id.clone(),
            edge_id: change.id.clone(),
            target_id: target.id.clone(),
        }]
    } else {
        path_edges.iter().map(|item| path_step(item.edge)).collect()
    };
    let mut evidence = change.evidence.clone();
    append_unique_evidence(
        &mut evidence,
        path_edges
            .iter()
            .flat_map(|item| item.evidence.iter().cloned())
            .collect(),
    );
    canonicalize_evidence(&mut evidence);
    let mut conditions = vec![change.condition.clone()];
    if !path_edges.is_empty() {
        conditions.push(combined_condition(&path_edges)?);
    }
    let condition = canonical_condition(&PolicyCondition::All { conditions })?;
    let mut context = combined_context(&path_edges);
    let profiles = if change.after.is_some() {
        &to.profiles
    } else {
        &from.profiles
    };
    let node_profile = change
        .profile_id
        .as_deref()
        .and_then(|profile_id| profiles.iter().find(|profile| profile.id == profile_id));
    for (key, value) in public_api_change_context(
        Some(target),
        change
            .after
            .as_ref()
            .and_then(|after| to.nodes.iter().find(|node| node.id == after.id)),
        node_profile,
        change.kind,
        &change.changed_fields,
    ) {
        context.entry(key).or_insert(value);
    }
    let suppression = applied_suppression(
        suppressions,
        &rule.id,
        &source.id,
        &target.id,
        profile_id,
        &context,
    );
    let id = PolicyViolation::stable_id(
        &rule.id,
        &source.id,
        &target.id,
        profile_id,
        &dependency_path,
    );
    Ok(PolicyViolation {
        id,
        rule_id: rule.id.clone(),
        severity: rule.severity,
        message: format!(
            "breaking public API {} for {} impacts {}",
            public_api_change_kind_name(change.kind),
            target.id,
            source.id
        ),
        source: policy_entity(source, rule.source.kind),
        target: policy_entity(target, rule.target.kind),
        dependency_path,
        profile_id: profile_id.map(ToOwned::to_owned),
        condition,
        evidence,
        change_id: Some(change.id.clone()),
        suppression,
    })
}

#[derive(Debug)]
struct AdmittedEdge<'a> {
    edge: &'a EdgeRecord,
    condition: PolicyCondition,
    evidence: Vec<PolicyEvidenceSpan>,
    context: BTreeMap<String, Value>,
}

#[derive(Debug)]
struct NodeEvidenceIndex<'a> {
    records: BTreeMap<&'a str, Vec<&'a EvidenceRecord>>,
}

impl<'a> NodeEvidenceIndex<'a> {
    fn new(snapshot: &'a GraphSnapshot) -> Self {
        let mut evidence_by_owner: BTreeMap<(&str, &str), Vec<&EvidenceRecord>> = BTreeMap::new();
        let mut records: BTreeMap<&str, Vec<&EvidenceRecord>> = BTreeMap::new();
        for evidence in &snapshot.evidence {
            evidence_by_owner
                .entry((evidence.owner_type.as_str(), evidence.owner_id.as_str()))
                .or_default()
                .push(evidence);
            if evidence.owner_type == "node" {
                records
                    .entry(evidence.owner_id.as_str())
                    .or_default()
                    .push(evidence);
            }
        }
        for edge in snapshot
            .edges
            .iter()
            .filter(|edge| matches!(edge.kind.as_str(), "declares" | "contains" | "route_entry"))
        {
            let mut related = evidence_by_owner
                .get(&("edge", edge.id.as_str()))
                .cloned()
                .unwrap_or_default();
            if related.is_empty()
                && let Some(site_id) = edge.site_id.as_deref()
            {
                related = evidence_by_owner
                    .get(&("site", site_id))
                    .cloned()
                    .unwrap_or_default();
            }
            records
                .entry(edge.target.as_str())
                .or_default()
                .extend(related);
        }
        for records in records.values_mut() {
            records.sort_by(|left, right| {
                (
                    left.ordinal,
                    &left.kind,
                    &left.path,
                    left.start_line,
                    left.start_column,
                    &left.owner_type,
                    &left.owner_id,
                )
                    .cmp(&(
                        right.ordinal,
                        &right.kind,
                        &right.path,
                        right.start_line,
                        right.start_column,
                        &right.owner_type,
                        &right.owner_id,
                    ))
            });
        }
        Self { records }
    }
}

#[derive(Debug)]
struct ResolvedSuppression<'a> {
    suppression: &'a PolicySuppression,
    source_ids: Option<BTreeSet<String>>,
    target_ids: Option<BTreeSet<String>>,
}

fn resolve_suppressions_bounded<'a>(
    snapshot: &GraphSnapshot,
    config: &'a PolicyConfig,
    rule_id: Option<&str>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<ResolvedSuppression<'a>>> {
    let mut resolved = Vec::with_capacity(config.suppressions.len());
    for suppression in &config.suppressions {
        work.step(is_cancelled)?;
        if rule_id.is_some_and(|rule_id| suppression.rule_id != rule_id) {
            continue;
        }
        let source_ids = suppression
            .scope
            .source
            .as_ref()
            .map(|selector| {
                resolve_selector_bounded(
                    snapshot,
                    selector,
                    &format!("suppression {:?} source", suppression.id),
                    work,
                    is_cancelled,
                )
                .and_then(|nodes| owned_node_id_set_bounded(&nodes, work, is_cancelled))
            })
            .transpose()?;
        let target_ids = suppression
            .scope
            .target
            .as_ref()
            .map(|selector| {
                resolve_selector_bounded(
                    snapshot,
                    selector,
                    &format!("suppression {:?} target", suppression.id),
                    work,
                    is_cancelled,
                )
                .and_then(|nodes| owned_node_id_set_bounded(&nodes, work, is_cancelled))
            })
            .transpose()?;
        work.step(is_cancelled)?;
        resolved.push(ResolvedSuppression {
            suppression,
            source_ids,
            target_ids,
        });
    }
    charge_sort_work(resolved.len(), work, is_cancelled)?;
    resolved.sort_by(|left, right| left.suppression.id.cmp(&right.suppression.id));
    Ok(resolved)
}

fn admitted_edges_with_options<'a>(
    snapshot: &'a GraphSnapshot,
    rule: &PolicyRule,
    apply_rule_condition: bool,
    require_evidence: bool,
) -> Result<Vec<AdmittedEdge<'a>>> {
    let mut work = PolicyEvaluationWork::new(usize::MAX);
    admitted_edges_with_options_bounded(
        snapshot,
        rule,
        apply_rule_condition,
        require_evidence,
        &mut work,
        &mut || false,
    )
}

fn admitted_edges_with_options_bounded<'a>(
    snapshot: &'a GraphSnapshot,
    rule: &PolicyRule,
    apply_rule_condition: bool,
    require_evidence: bool,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<AdmittedEdge<'a>>> {
    let mut profiles = BTreeMap::new();
    for profile in &snapshot.profiles {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(profiles.len(), 1, work, is_cancelled)?;
        profiles.insert(profile.id.as_str(), profile);
    }
    let evidence: BTreeMap<_, Vec<_>> = {
        let mut by_owner: BTreeMap<(&str, &str), Vec<&EvidenceRecord>> = BTreeMap::new();
        for item in &snapshot.evidence {
            work.step(is_cancelled)?;
            charge_ordered_collection_work(by_owner.len(), 2, work, is_cancelled)?;
            by_owner
                .entry((item.owner_type.as_str(), item.owner_id.as_str()))
                .or_default()
                .push(item);
        }
        by_owner
    };
    let allowed_precisions = serialized_names(&rule.precisions)?;
    let allowed_statuses = serialized_names(&rule.resolution_statuses)?;
    let mut admitted = Vec::new();

    for edge in &snapshot.edges {
        work.step(is_cancelled)?;
        if !profile_matches_bounded(&rule.profiles, &edge.profile_id, work, is_cancelled)?
            || !allowed_precisions.contains(edge.precision.as_str())
            || !allowed_statuses.contains(edge.resolution_status.as_str())
        {
            continue;
        }

        let condition: PolicyCondition = serde_json::from_value(edge.condition.clone())
            .with_context(|| format!("edge {:?} has an invalid policy condition", edge.id))?;
        let mut context = edge_context_bounded(
            edge,
            profiles.get(edge.profile_id.as_str()).copied(),
            work,
            is_cancelled,
        )?;
        if evaluate_edge_condition(&condition, &context) == Some(false) {
            continue;
        }
        add_condition_facts(&condition, &mut context);
        if apply_rule_condition && evaluate_condition(&rule.condition, &context) != Some(true) {
            continue;
        }

        let spans = select_evidence_bounded(edge, &rule.evidence, &evidence, work, is_cancelled)?;
        if require_evidence && spans.len() < usize::try_from(rule.evidence.minimum_spans)? {
            continue;
        }
        work.step(is_cancelled)?;
        admitted.push(AdmittedEdge {
            edge,
            condition: canonical_condition(&condition)?,
            evidence: spans,
            context,
        });
    }
    charge_sort_work(admitted.len(), work, is_cancelled)?;
    admitted.sort_by(|left, right| {
        (
            &left.edge.profile_id,
            &left.edge.source,
            &left.edge.target,
            &left.edge.id,
        )
            .cmp(&(
                &right.edge.profile_id,
                &right.edge.source,
                &right.edge.target,
                &right.edge.id,
            ))
    });
    Ok(admitted)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_runtime_boundary(
    rule: &PolicyRule,
    snapshot: &GraphSnapshot,
    sources: &[&NodeRecord],
    target_ids: &BTreeSet<&str>,
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PolicyViolation>> {
    let admitted =
        admitted_edges_with_options_bounded(snapshot, rule, false, true, work, is_cancelled)?;
    let mut by_profile: BTreeMap<&str, Vec<&AdmittedEdge<'_>>> = BTreeMap::new();
    for item in &admitted {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(by_profile.len(), 1, work, is_cancelled)?;
        by_profile
            .entry(item.edge.profile_id.as_str())
            .or_default()
            .push(item);
    }

    let mut output = BTreeMap::new();
    for (profile_id, edges) in by_profile {
        work.step(is_cancelled)?;
        let adjacency = adjacency_bounded(&edges, work, is_cancelled)?;
        let mut boundaries = Vec::new();
        for item in &edges {
            work.step(is_cancelled)?;
            if matches!(
                item.edge.kind.as_str(),
                "client_boundary" | "server_boundary"
            ) && target_ids.contains(item.edge.target.as_str())
                && evaluate_condition(&rule.condition, &item.context) == Some(true)
            {
                boundaries.push(*item);
            }
        }

        for source in sources {
            work.step(is_cancelled)?;
            let mut visited = BTreeSet::from([source.id.clone()]);
            let mut predecessor: HashMap<String, &AdmittedEdge<'_>> = HashMap::new();
            let mut queue = VecDeque::from([source.id.clone()]);
            while let Some(current) = queue.pop_front() {
                work.step(is_cancelled)?;
                for item in adjacency.get(current.as_str()).into_iter().flatten() {
                    work.step(is_cancelled)?;
                    charge_ordered_collection_work(visited.len(), 1, work, is_cancelled)?;
                    if visited.insert(item.edge.target.clone()) {
                        predecessor.insert(item.edge.target.clone(), item);
                        queue.push_back(item.edge.target.clone());
                    }
                }
            }

            for boundary in &boundaries {
                work.step(is_cancelled)?;
                let mut path_edges = if source.id == boundary.edge.source {
                    Vec::new()
                } else if visited.contains(&boundary.edge.source) {
                    reconstruct_path_bounded(
                        &source.id,
                        &boundary.edge.source,
                        &predecessor,
                        work,
                        is_cancelled,
                    )?
                } else {
                    continue;
                };
                path_edges.push(boundary);
                let mut path = Vec::with_capacity(path_edges.len());
                for item in &path_edges {
                    work.step(is_cancelled)?;
                    path.push(path_step(item.edge));
                }
                work.step(is_cancelled)?;
                let violation = make_violation_bounded(
                    rule,
                    nodes,
                    &source.id,
                    &boundary.edge.target,
                    Some(profile_id),
                    path,
                    path_edges,
                    format!(
                        "{} {} is reachable from {} to {}",
                        rule_kind_name(&rule.kind),
                        boundary.edge.kind,
                        source.id,
                        boundary.edge.target
                    ),
                    suppressions,
                    work,
                    is_cancelled,
                )?;
                work.step(is_cancelled)?;
                charge_ordered_collection_work(output.len(), 1, work, is_cancelled)?;
                output.entry(violation.id.clone()).or_insert(violation);
            }
        }
    }
    let mut violations = Vec::with_capacity(output.len());
    for violation in output.into_values() {
        work.step(is_cancelled)?;
        violations.push(violation);
    }
    Ok(violations)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_direct_bounded(
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    source_ids: &BTreeSet<&str>,
    target_ids: &BTreeSet<&str>,
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PolicyViolation>> {
    let mut violations = Vec::new();
    for item in admitted {
        work.step(is_cancelled)?;
        if !source_ids.contains(item.edge.source.as_str())
            || !target_ids.contains(item.edge.target.as_str())
        {
            continue;
        }
        work.step(is_cancelled)?;
        let path = vec![path_step(item.edge)];
        let violation = make_violation_bounded(
            rule,
            nodes,
            &item.edge.source,
            &item.edge.target,
            Some(&item.edge.profile_id),
            path,
            vec![item],
            format!(
                "{} dependency from {} to {} is forbidden",
                rule_kind_name(&rule.kind),
                item.edge.source,
                item.edge.target
            ),
            suppressions,
            work,
            is_cancelled,
        )?;
        work.step(is_cancelled)?;
        violations.push(violation);
    }
    Ok(violations)
}

fn evaluate_cycles(
    snapshot: &GraphSnapshot,
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    source_ids: &BTreeSet<&str>,
    target_ids: &BTreeSet<&str>,
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
) -> Result<Vec<PolicyViolation>> {
    let level = cycle_level(rule.source.kind)
        .with_context(|| format!("cycle rule {:?} uses an unsupported selector kind", rule.id))?;
    let cycle_nodes: BTreeSet<_> = source_ids.union(target_ids).copied().collect();
    let mut by_profile: BTreeMap<&str, Vec<&AdmittedEdge<'_>>> = BTreeMap::new();
    for item in admitted {
        if cycle_nodes.contains(item.edge.source.as_str())
            && cycle_nodes.contains(item.edge.target.as_str())
        {
            by_profile
                .entry(item.edge.profile_id.as_str())
                .or_default()
                .push(item);
        }
    }

    let mut output = Vec::new();
    for (profile_id, edges) in by_profile {
        let mut filtered = snapshot.clone();
        filtered.edges = edges.iter().map(|item| item.edge.clone()).collect();
        for cycle in cycles(&filtered, level) {
            let ring = &cycle.node_ids[..cycle.node_ids.len() - 1];
            if !ring.iter().any(|node| source_ids.contains(node.as_str()))
                || !ring.iter().any(|node| target_ids.contains(node.as_str()))
            {
                continue;
            }
            let Some(start) = ring
                .iter()
                .filter(|node| source_ids.contains(node.as_str()))
                .min()
            else {
                continue;
            };
            let start_index = ring
                .iter()
                .position(|node| node == start)
                .context("cycle start disappeared")?;
            let mut node_path = ring[start_index..].to_vec();
            node_path.extend_from_slice(&ring[..start_index]);
            node_path.push(start.clone());

            let mut path = Vec::new();
            let mut path_edges = Vec::new();
            for pair in node_path.windows(2) {
                let item = edges
                    .iter()
                    .filter(|item| item.edge.source == pair[0] && item.edge.target == pair[1])
                    .min_by(|left, right| left.edge.id.cmp(&right.edge.id))
                    .with_context(|| {
                        format!(
                            "cycle query returned a step without an admitted edge: {} -> {}",
                            pair[0], pair[1]
                        )
                    })?;
                path.push(path_step(item.edge));
                path_edges.push(*item);
            }
            output.push(make_violation(
                rule,
                nodes,
                start,
                start,
                Some(profile_id),
                path,
                path_edges,
                format!(
                    "{} cycle contains {} dependency steps",
                    cycle.level,
                    node_path.len() - 1
                ),
                suppressions,
            )?);
        }
    }
    Ok(output)
}

fn evaluate_depth(
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    sources: &[&NodeRecord],
    targets: &[&NodeRecord],
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
) -> Result<Vec<PolicyViolation>> {
    let max = rule.threshold.context("depth rule threshold")?.max;
    let mut by_profile: BTreeMap<&str, Vec<&AdmittedEdge<'_>>> = BTreeMap::new();
    for item in admitted {
        by_profile
            .entry(item.edge.profile_id.as_str())
            .or_default()
            .push(item);
    }
    let mut output = Vec::new();

    for (profile_id, edges) in by_profile {
        let adjacency = adjacency(&edges);
        for source in sources {
            let mut distance = BTreeMap::from([(source.id.clone(), 0_u64)]);
            let mut predecessor: HashMap<String, &AdmittedEdge<'_>> = HashMap::new();
            let mut queue = VecDeque::from([source.id.clone()]);
            while let Some(current) = queue.pop_front() {
                let next_distance = distance[&current] + 1;
                for edge in adjacency.get(current.as_str()).into_iter().flatten() {
                    if !distance.contains_key(&edge.edge.target) {
                        distance.insert(edge.edge.target.clone(), next_distance);
                        predecessor.insert(edge.edge.target.clone(), edge);
                        queue.push_back(edge.edge.target.clone());
                    }
                }
            }

            for target in targets {
                let Some(&actual) = distance.get(&target.id) else {
                    continue;
                };
                if actual <= max {
                    continue;
                }
                let path_edges = reconstruct_path(&source.id, &target.id, &predecessor)?;
                let path = path_edges.iter().map(|item| path_step(item.edge)).collect();
                output.push(make_violation(
                    rule,
                    nodes,
                    &source.id,
                    &target.id,
                    Some(profile_id),
                    path,
                    path_edges,
                    format!(
                        "dependency depth from {} to {} is {actual}, exceeding {max}",
                        source.id, target.id
                    ),
                    suppressions,
                )?);
            }
        }
    }
    Ok(output)
}

fn evaluate_fan_out(
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    sources: &[&NodeRecord],
    target_ids: &BTreeSet<&str>,
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
) -> Result<Vec<PolicyViolation>> {
    let max = rule.threshold.context("fan-out rule threshold")?.max;
    let mut output = Vec::new();
    for source in sources {
        let mut groups: BTreeMap<&str, BTreeMap<&str, &AdmittedEdge<'_>>> = BTreeMap::new();
        for item in admitted.iter().filter(|item| {
            item.edge.source == source.id && target_ids.contains(item.edge.target.as_str())
        }) {
            groups
                .entry(item.edge.profile_id.as_str())
                .or_default()
                .entry(item.edge.target.as_str())
                .and_modify(|current| {
                    if item.edge.id < current.edge.id {
                        *current = item;
                    }
                })
                .or_insert(item);
        }
        for (profile_id, targets) in groups {
            let count = u64::try_from(targets.len())?;
            if count <= max {
                continue;
            }
            let witness = overflow_witness(&targets, max)?;
            output.push(make_violation(
                rule,
                nodes,
                &source.id,
                &witness.edge.target,
                Some(profile_id),
                vec![path_step(witness.edge)],
                vec![witness],
                format!("fan-out for {} is {count}, exceeding {max}", source.id),
                suppressions,
            )?);
        }
    }
    Ok(output)
}

fn evaluate_fan_in(
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    source_ids: &BTreeSet<&str>,
    targets: &[&NodeRecord],
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
) -> Result<Vec<PolicyViolation>> {
    let max = rule.threshold.context("fan-in rule threshold")?.max;
    let mut output = Vec::new();
    for target in targets {
        let mut groups: BTreeMap<&str, BTreeMap<&str, &AdmittedEdge<'_>>> = BTreeMap::new();
        for item in admitted.iter().filter(|item| {
            item.edge.target == target.id && source_ids.contains(item.edge.source.as_str())
        }) {
            groups
                .entry(item.edge.profile_id.as_str())
                .or_default()
                .entry(item.edge.source.as_str())
                .and_modify(|current| {
                    if item.edge.id < current.edge.id {
                        *current = item;
                    }
                })
                .or_insert(item);
        }
        for (profile_id, sources) in groups {
            let count = u64::try_from(sources.len())?;
            if count <= max {
                continue;
            }
            let witness = overflow_witness(&sources, max)?;
            output.push(make_violation(
                rule,
                nodes,
                &witness.edge.source,
                &target.id,
                Some(profile_id),
                vec![path_step(witness.edge)],
                vec![witness],
                format!("fan-in for {} is {count}, exceeding {max}", target.id),
                suppressions,
            )?);
        }
    }
    Ok(output)
}

fn overflow_witness<'a>(
    entries: &'a BTreeMap<&str, &'a AdmittedEdge<'a>>,
    max: u64,
) -> Result<&'a AdmittedEdge<'a>> {
    let index = usize::try_from(max)?;
    entries
        .values()
        .nth(index)
        .copied()
        .context("threshold overflow did not have a witness edge")
}

fn adjacency<'a>(edges: &[&'a AdmittedEdge<'a>]) -> BTreeMap<&'a str, Vec<&'a AdmittedEdge<'a>>> {
    let mut work = PolicyEvaluationWork::new(usize::MAX);
    adjacency_bounded(edges, &mut work, &mut || false)
        .expect("unbounded, non-cancellable adjacency construction cannot fail")
}

fn adjacency_bounded<'a>(
    edges: &[&'a AdmittedEdge<'a>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<&'a str, Vec<&'a AdmittedEdge<'a>>>> {
    let mut adjacency: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for edge in edges {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(adjacency.len(), 1, work, is_cancelled)?;
        adjacency
            .entry(edge.edge.source.as_str())
            .or_default()
            .push(*edge);
    }
    for outgoing in adjacency.values_mut() {
        charge_sort_work(outgoing.len(), work, is_cancelled)?;
        outgoing.sort_by(|left, right| {
            (&left.edge.target, &left.edge.id).cmp(&(&right.edge.target, &right.edge.id))
        });
    }
    Ok(adjacency)
}

fn reconstruct_path<'a>(
    source: &str,
    target: &str,
    predecessor: &HashMap<String, &'a AdmittedEdge<'a>>,
) -> Result<Vec<&'a AdmittedEdge<'a>>> {
    let mut work = PolicyEvaluationWork::new(usize::MAX);
    reconstruct_path_bounded(source, target, predecessor, &mut work, &mut || false)
}

fn reconstruct_path_bounded<'a>(
    source: &str,
    target: &str,
    predecessor: &HashMap<String, &'a AdmittedEdge<'a>>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<&'a AdmittedEdge<'a>>> {
    let mut current = target;
    let mut reversed = Vec::new();
    while current != source {
        work.step(is_cancelled)?;
        let edge = predecessor
            .get(current)
            .copied()
            .with_context(|| format!("policy path reconstruction failed at {current}"))?;
        reversed.push(edge);
        current = edge.edge.source.as_str();
    }
    reversed.reverse();
    Ok(reversed)
}

#[allow(clippy::too_many_arguments)]
fn make_violation(
    rule: &PolicyRule,
    nodes: &BTreeMap<&str, &NodeRecord>,
    source_id: &str,
    target_id: &str,
    profile_id: Option<&str>,
    dependency_path: Vec<PolicyPathStep>,
    path_edges: Vec<&AdmittedEdge<'_>>,
    message: String,
    suppressions: &[ResolvedSuppression<'_>],
) -> Result<PolicyViolation> {
    let mut work = PolicyEvaluationWork::new(usize::MAX);
    make_violation_bounded(
        rule,
        nodes,
        source_id,
        target_id,
        profile_id,
        dependency_path,
        path_edges,
        message,
        suppressions,
        &mut work,
        &mut || false,
    )
}

#[allow(clippy::too_many_arguments)]
fn make_violation_bounded(
    rule: &PolicyRule,
    nodes: &BTreeMap<&str, &NodeRecord>,
    source_id: &str,
    target_id: &str,
    profile_id: Option<&str>,
    dependency_path: Vec<PolicyPathStep>,
    path_edges: Vec<&AdmittedEdge<'_>>,
    message: String,
    suppressions: &[ResolvedSuppression<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyViolation> {
    work.step(is_cancelled)?;
    let source_node = nodes
        .get(source_id)
        .copied()
        .with_context(|| format!("policy source node {source_id:?} is missing"))?;
    work.step(is_cancelled)?;
    let target_node = nodes
        .get(target_id)
        .copied()
        .with_context(|| format!("policy target node {target_id:?} is missing"))?;
    let mut evidence = Vec::new();
    for item in &path_edges {
        work.step(is_cancelled)?;
        for span in &item.evidence {
            work.step(is_cancelled)?;
            evidence.push(span.clone());
        }
    }
    canonicalize_evidence_bounded(&mut evidence, work, is_cancelled)?;
    let condition = combined_condition_bounded(&path_edges, work, is_cancelled)?;
    let context = combined_context_bounded(&path_edges, work, is_cancelled)?;
    let suppression = applied_suppression_bounded(
        suppressions,
        &rule.id,
        source_id,
        target_id,
        profile_id,
        &context,
        work,
        is_cancelled,
    )?;
    work.steps(dependency_path.len().saturating_add(1), is_cancelled)?;
    let id =
        PolicyViolation::stable_id(&rule.id, source_id, target_id, profile_id, &dependency_path);
    Ok(PolicyViolation {
        id,
        rule_id: rule.id.clone(),
        severity: rule.severity,
        message,
        source: PolicyEntity {
            id: source_id.to_owned(),
            kind: rule.source.kind,
            locator: source_node.locator.clone(),
        },
        target: PolicyEntity {
            id: target_id.to_owned(),
            kind: rule.target.kind,
            locator: target_node.locator.clone(),
        },
        dependency_path,
        profile_id: profile_id.map(ToOwned::to_owned),
        condition,
        evidence,
        change_id: None,
        suppression,
    })
}

fn applied_suppression(
    suppressions: &[ResolvedSuppression<'_>],
    rule_id: &str,
    source_id: &str,
    target_id: &str,
    profile_id: Option<&str>,
    context: &BTreeMap<String, Value>,
) -> Option<AppliedPolicySuppression> {
    suppressions
        .iter()
        .filter(|resolved| resolved.suppression.rule_id == rule_id)
        .find(|resolved| {
            let scope = &resolved.suppression.scope;
            resolved
                .source_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(source_id))
                && resolved
                    .target_ids
                    .as_ref()
                    .is_none_or(|ids| ids.contains(target_id))
                && profile_id.map_or_else(
                    || scope.profiles == PolicyProfileFilter::default(),
                    |profile| profile_matches(&scope.profiles, profile),
                )
                && scope
                    .condition
                    .as_ref()
                    .is_none_or(|condition| evaluate_condition(condition, context) == Some(true))
        })
        .map(|resolved| AppliedPolicySuppression {
            id: resolved.suppression.id.clone(),
            reason: resolved.suppression.reason.clone(),
        })
}

#[allow(clippy::too_many_arguments)]
fn applied_suppression_bounded(
    suppressions: &[ResolvedSuppression<'_>],
    rule_id: &str,
    source_id: &str,
    target_id: &str,
    profile_id: Option<&str>,
    context: &BTreeMap<String, Value>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<AppliedPolicySuppression>> {
    for resolved in suppressions {
        work.step(is_cancelled)?;
        if resolved.suppression.rule_id != rule_id {
            continue;
        }
        let scope = &resolved.suppression.scope;
        if !resolved
            .source_ids
            .as_ref()
            .is_none_or(|ids| ids.contains(source_id))
            || !resolved
                .target_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(target_id))
        {
            continue;
        }
        if let Some(profile_id) = profile_id {
            if !profile_matches_bounded(&scope.profiles, profile_id, work, is_cancelled)? {
                continue;
            }
        } else if scope.profiles != PolicyProfileFilter::default() {
            continue;
        }
        if let Some(condition) = &scope.condition {
            work.step(is_cancelled)?;
            if evaluate_condition(condition, context) != Some(true) {
                continue;
            }
        }
        work.step(is_cancelled)?;
        return Ok(Some(AppliedPolicySuppression {
            id: resolved.suppression.id.clone(),
            reason: resolved.suppression.reason.clone(),
        }));
    }
    Ok(None)
}

fn combined_context(edges: &[&AdmittedEdge<'_>]) -> BTreeMap<String, Value> {
    let mut combined: BTreeMap<String, Option<Value>> = BTreeMap::new();
    for edge in edges {
        for (key, value) in &edge.context {
            combined
                .entry(key.clone())
                .and_modify(|current| {
                    if current.as_ref().is_some_and(|existing| existing != value) {
                        *current = None;
                    }
                })
                .or_insert_with(|| Some(value.clone()));
        }
    }
    combined
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
        .collect()
}

fn combined_context_bounded(
    edges: &[&AdmittedEdge<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<String, Value>> {
    let mut combined: BTreeMap<String, Option<Value>> = BTreeMap::new();
    for edge in edges {
        work.step(is_cancelled)?;
        for (key, value) in &edge.context {
            work.step(is_cancelled)?;
            charge_json_value_work(value, work, is_cancelled)?;
            combined
                .entry(key.clone())
                .and_modify(|current| {
                    if current.as_ref().is_some_and(|existing| existing != value) {
                        *current = None;
                    }
                })
                .or_insert_with(|| Some(value.clone()));
        }
    }
    let mut output = BTreeMap::new();
    for (key, value) in combined {
        work.step(is_cancelled)?;
        if let Some(value) = value {
            output.insert(key, value);
        }
    }
    Ok(output)
}

fn resolve_selector<'a>(
    snapshot: &'a GraphSnapshot,
    selector: &PolicySelector,
    description: &str,
) -> Result<Vec<&'a NodeRecord>> {
    let mut work = PolicyEvaluationWork::new(usize::MAX);
    resolve_selector_bounded(snapshot, selector, description, &mut work, &mut || false)
}

fn resolve_selector_bounded<'a>(
    snapshot: &'a GraphSnapshot,
    selector: &PolicySelector,
    description: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<&'a NodeRecord>> {
    let mut matches = Vec::new();
    for node in &snapshot.nodes {
        work.step(is_cancelled)?;
        if selector_matches_node_bounded(node, selector, work, is_cancelled)? {
            work.step(is_cancelled)?;
            matches.push(node);
        }
    }
    charge_sort_work(matches.len(), work, is_cancelled)?;
    matches.sort_by(|left, right| left.id.cmp(&right.id));
    if selector.cardinality == PolicySelectorCardinality::One && matches.len() != 1 {
        bail!(
            "policy selector {description} must resolve to exactly one node, but matched {}",
            matches.len()
        );
    }
    Ok(matches)
}

fn borrowed_node_id_set_bounded<'a>(
    nodes: &[&'a NodeRecord],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeSet<&'a str>> {
    let mut ids = BTreeSet::new();
    for node in nodes {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(ids.len(), 1, work, is_cancelled)?;
        ids.insert(node.id.as_str());
    }
    Ok(ids)
}

fn owned_node_id_set_bounded(
    nodes: &[&NodeRecord],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for node in nodes {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(ids.len(), 1, work, is_cancelled)?;
        ids.insert(node.id.clone());
    }
    Ok(ids)
}

fn selector_matches_node(node: &NodeRecord, selector: &PolicySelector) -> bool {
    if !node_kind_matches(node, selector.kind) {
        return false;
    }
    if !selector.scope.paths.is_empty()
        && node_path(node).is_none_or(|value| !patterns_match(&selector.scope.paths, value))
    {
        return false;
    }
    if !selector.scope.packages.is_empty()
        && node_package(node).is_none_or(|value| !patterns_match(&selector.scope.packages, value))
    {
        return false;
    }
    let Some(value) = selector_field(node, selector.field) else {
        return false;
    };
    pattern_matches(selector.match_kind, &selector.value, value)
        && !selector.exclude.iter().any(|exclude| {
            selector_field(node, exclude.field)
                .is_some_and(|value| pattern_matches(exclude.match_kind, &exclude.value, value))
        })
}

fn selector_matches_node_bounded(
    node: &NodeRecord,
    selector: &PolicySelector,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool> {
    if !node_kind_matches(node, selector.kind) {
        return Ok(false);
    }
    if !selector.scope.paths.is_empty() {
        let Some(value) = node_path(node) else {
            return Ok(false);
        };
        if !patterns_match_bounded(&selector.scope.paths, value, work, is_cancelled)? {
            return Ok(false);
        }
    }
    if !selector.scope.packages.is_empty() {
        let Some(value) = node_package(node) else {
            return Ok(false);
        };
        if !patterns_match_bounded(&selector.scope.packages, value, work, is_cancelled)? {
            return Ok(false);
        }
    }
    let Some(value) = selector_field(node, selector.field) else {
        return Ok(false);
    };
    work.step(is_cancelled)?;
    if !pattern_matches(selector.match_kind, &selector.value, value) {
        return Ok(false);
    }
    for exclude in &selector.exclude {
        work.step(is_cancelled)?;
        if selector_field(node, exclude.field)
            .is_some_and(|value| pattern_matches(exclude.match_kind, &exclude.value, value))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn node_kind_matches(node: &NodeRecord, kind: PolicySelectorKind) -> bool {
    match kind {
        PolicySelectorKind::Package => node.kind == "package_instance" || node.kind == "package",
        PolicySelectorKind::File => node.kind == "file",
        PolicySelectorKind::Symbol => node.kind == "symbol",
        PolicySelectorKind::Type => node.kind == "type",
        PolicySelectorKind::Route => node.kind == "route",
        PolicySelectorKind::Component => node.kind == "component",
    }
}

fn selector_field(node: &NodeRecord, field: PolicySelectorField) -> Option<&str> {
    match field {
        PolicySelectorField::Id => Some(&node.id),
        PolicySelectorField::Path => node_path(node),
        PolicySelectorField::Locator => Some(&node.locator),
        PolicySelectorField::DisplayName => Some(&node.display_name),
    }
}

fn node_path(node: &NodeRecord) -> Option<&str> {
    string_property(&node.properties, &["path", "relative_path"]).or_else(|| {
        node.properties
            .get("canonical_identity")
            .and_then(|identity| string_property(identity, &["path", "relative_path"]))
    })
}

fn node_package(node: &NodeRecord) -> Option<&str> {
    string_property(
        &node.properties,
        &[
            "package_locator",
            "package_id",
            "package_path",
            "package",
            "locator",
        ],
    )
    .or_else(|| {
        node.properties
            .get("canonical_identity")
            .and_then(|identity| string_property(identity, &["package_locator"]))
    })
    .or_else(|| {
        matches!(node.kind.as_str(), "package" | "package_instance")
            .then_some(node.locator.as_str())
    })
}

fn node_profile_id(node: &NodeRecord) -> Option<&str> {
    string_property(&node.properties, &["profile_id"]).or_else(|| {
        node.properties
            .get("canonical_identity")
            .and_then(|identity| string_property(identity, &["profile_id"]))
    })
}

fn optional_profile_matches(filter: &PolicyProfileFilter, profile_id: Option<&str>) -> bool {
    profile_id.map_or_else(
        || filter == &PolicyProfileFilter::default(),
        |profile_id| profile_matches(filter, profile_id),
    )
}

fn policy_entity(node: &NodeRecord, kind: PolicySelectorKind) -> PolicyEntity {
    PolicyEntity {
        id: node.id.clone(),
        kind,
        locator: node.locator.clone(),
    }
}

fn public_api_change_context(
    before: Option<&NodeRecord>,
    after: Option<&NodeRecord>,
    profile: Option<&ProfileRecord>,
    kind: PublicApiChangeKind,
    changed_fields: &[String],
) -> BTreeMap<String, Value> {
    let mut context = BTreeMap::new();
    if let Some(profile) = profile {
        merge_object(&mut context, &profile.environment);
        merge_object(&mut context, &profile.properties);
        context.insert(
            "language".to_owned(),
            Value::String(profile.language.clone()),
        );
        if let Some(target) = &profile.target {
            context.insert("target".to_owned(), Value::String(target.clone()));
        }
        if let Some(command) = &profile.command {
            context.insert("command".to_owned(), Value::String(command.clone()));
        }
        context.insert(
            "features".to_owned(),
            Value::Array(
                profile
                    .features
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        context.insert("profile".to_owned(), Value::String(profile.id.clone()));
        context.insert("profile_id".to_owned(), Value::String(profile.id.clone()));
    }
    if let Some(node) = after.or(before) {
        merge_object(&mut context, &node.properties);
    }
    context.insert(
        "change".to_owned(),
        serde_json::json!({
            "kind": public_api_change_kind_name(kind),
            "breaking": kind != PublicApiChangeKind::Added,
            "changed_fields": changed_fields,
        }),
    );
    context
}

fn string_property<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
}

fn patterns_match(patterns: &[PolicyPattern], value: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| pattern_matches(pattern.match_kind, &pattern.value, value))
}

fn patterns_match_bounded(
    patterns: &[PolicyPattern],
    value: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool> {
    for pattern in patterns {
        work.step(is_cancelled)?;
        if pattern_matches(pattern.match_kind, &pattern.value, value) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn profile_matches(filter: &PolicyProfileFilter, profile_id: &str) -> bool {
    (filter.include.is_empty() || patterns_match(&filter.include, profile_id))
        && !patterns_match(&filter.exclude, profile_id)
}

fn profile_matches_bounded(
    filter: &PolicyProfileFilter,
    profile_id: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool> {
    let included = if filter.include.is_empty() {
        true
    } else {
        patterns_match_bounded(&filter.include, profile_id, work, is_cancelled)?
    };
    if !included {
        return Ok(false);
    }
    Ok(!patterns_match_bounded(
        &filter.exclude,
        profile_id,
        work,
        is_cancelled,
    )?)
}

fn pattern_matches(kind: PolicyMatchKind, pattern: &str, value: &str) -> bool {
    match kind {
        PolicyMatchKind::Exact => value == pattern,
        PolicyMatchKind::Prefix => value.starts_with(pattern),
        PolicyMatchKind::Glob => glob_matches(pattern, value),
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    fn visit(
        pattern: &[char],
        value: &[char],
        pi: usize,
        vi: usize,
        memo: &mut HashMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(result) = memo.get(&(pi, vi)) {
            return *result;
        }
        let result = if pi == pattern.len() {
            vi == value.len()
        } else if pattern[pi] == '*' {
            let double = pattern.get(pi + 1) == Some(&'*');
            let next_pattern = pi + usize::from(double) + 1;
            visit(pattern, value, next_pattern, vi, memo)
                || (double
                    && pattern.get(next_pattern) == Some(&'/')
                    && visit(pattern, value, next_pattern + 1, vi, memo))
                || (vi < value.len()
                    && (double || value[vi] != '/')
                    && visit(pattern, value, pi, vi + 1, memo))
        } else if vi < value.len()
            && ((pattern[pi] == '?' && value[vi] != '/') || pattern[pi] == value[vi])
        {
            visit(pattern, value, pi + 1, vi + 1, memo)
        } else {
            false
        };
        memo.insert((pi, vi), result);
        result
    }

    visit(
        &pattern.chars().collect::<Vec<_>>(),
        &value.chars().collect::<Vec<_>>(),
        0,
        0,
        &mut HashMap::new(),
    )
}

fn edge_context_bounded(
    edge: &EdgeRecord,
    profile: Option<&ProfileRecord>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<String, Value>> {
    work.steps(8, is_cancelled)?;
    if let Some(profile) = profile {
        charge_json_value_work(&profile.environment, work, is_cancelled)?;
        charge_json_value_work(&profile.properties, work, is_cancelled)?;
        work.steps(profile.features.len(), is_cancelled)?;
    }
    Ok(edge_context(edge, profile))
}

fn edge_context(edge: &EdgeRecord, profile: Option<&ProfileRecord>) -> BTreeMap<String, Value> {
    let mut context = BTreeMap::new();
    if let Some(profile) = profile {
        merge_object(&mut context, &profile.environment);
        merge_object(&mut context, &profile.properties);
        context.insert(
            "language".to_owned(),
            Value::String(profile.language.clone()),
        );
        if let Some(target) = &profile.target {
            context.insert("target".to_owned(), Value::String(target.clone()));
        }
        if let Some(command) = &profile.command {
            context.insert("command".to_owned(), Value::String(command.clone()));
        }
        context.insert(
            "features".to_owned(),
            Value::Array(
                profile
                    .features
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    context.insert("profile".to_owned(), Value::String(edge.profile_id.clone()));
    context.insert(
        "profile_id".to_owned(),
        Value::String(edge.profile_id.clone()),
    );
    context.insert("phase".to_owned(), Value::String(edge.phase.clone()));
    context.insert(
        "environment".to_owned(),
        Value::String(edge.environment.clone()),
    );
    context.insert(
        "precision".to_owned(),
        Value::String(edge.precision.clone()),
    );
    context.insert(
        "resolution_status".to_owned(),
        Value::String(edge.resolution_status.clone()),
    );
    context.insert("generated".to_owned(), Value::Bool(edge.generated));
    context
}

fn merge_object(context: &mut BTreeMap<String, Value>, value: &Value) {
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            context.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
}

fn evaluate_condition(
    condition: &PolicyCondition,
    context: &BTreeMap<String, Value>,
) -> Option<bool> {
    match condition {
        PolicyCondition::All { conditions } => {
            let values: Vec<_> = conditions
                .iter()
                .map(|condition| evaluate_condition(condition, context))
                .collect();
            if values.contains(&Some(false)) {
                Some(false)
            } else if values.iter().all(|value| *value == Some(true)) {
                Some(true)
            } else {
                None
            }
        }
        PolicyCondition::Any { conditions } => {
            let values: Vec<_> = conditions
                .iter()
                .map(|condition| evaluate_condition(condition, context))
                .collect();
            if values.contains(&Some(true)) {
                Some(true)
            } else if values.iter().all(|value| *value == Some(false)) {
                Some(false)
            } else {
                None
            }
        }
        PolicyCondition::Not { condition } => {
            evaluate_condition(condition, context).map(|value| !value)
        }
        PolicyCondition::Eq { key, value } => {
            lookup_context(context, key).map(|actual| condition_values_equal(actual, value))
        }
        PolicyCondition::In { key, values } => lookup_context(context, key).map(|actual| {
            values
                .iter()
                .any(|value| condition_values_equal(actual, value))
        }),
        PolicyCondition::Defined { key } => {
            Some(lookup_context(context, key).is_some_and(|value| !value.is_null()))
        }
    }
}

fn evaluate_edge_condition(
    condition: &PolicyCondition,
    context: &BTreeMap<String, Value>,
) -> Option<bool> {
    match condition {
        PolicyCondition::All { conditions } => combine_all(
            conditions
                .iter()
                .map(|condition| evaluate_edge_condition(condition, context)),
        ),
        PolicyCondition::Any { conditions } => combine_any(
            conditions
                .iter()
                .map(|condition| evaluate_edge_condition(condition, context)),
        ),
        PolicyCondition::Not { condition } => {
            evaluate_edge_condition(condition, context).map(|value| !value)
        }
        PolicyCondition::Eq { key, value } => {
            lookup_context(context, key).map(|actual| condition_values_equal(actual, value))
        }
        PolicyCondition::In { key, values } => lookup_context(context, key).map(|actual| {
            values
                .iter()
                .any(|value| condition_values_equal(actual, value))
        }),
        // A stored edge already belongs to an evaluated profile. Missing
        // metadata therefore means "not enough information to contradict the
        // edge", not that the edge is inactive.
        PolicyCondition::Defined { key } => {
            lookup_context(context, key).map(|value| !value.is_null())
        }
    }
}

fn combine_all(values: impl Iterator<Item = Option<bool>>) -> Option<bool> {
    let values: Vec<_> = values.collect();
    if values.contains(&Some(false)) {
        Some(false)
    } else if values.iter().all(|value| *value == Some(true)) {
        Some(true)
    } else {
        None
    }
}

fn combine_any(values: impl Iterator<Item = Option<bool>>) -> Option<bool> {
    let values: Vec<_> = values.collect();
    if values.contains(&Some(true)) {
        Some(true)
    } else if values.iter().all(|value| *value == Some(false)) {
        Some(false)
    } else {
        None
    }
}

fn lookup_context<'a>(context: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a Value> {
    if let Some(value) = context.get(key) {
        return Some(value);
    }
    let mut segments = key.split('.');
    let mut value = context.get(segments.next()?)?;
    for segment in segments {
        value = value.get(segment)?;
    }
    Some(value)
}

fn condition_values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => match (left.as_i128(), right.as_i128()) {
            (Some(left), Some(right)) => left == right,
            (Some(integer), None) => right
                .as_f64()
                .is_some_and(|float| float.fract() == 0.0 && integer == float as i128),
            (None, Some(integer)) => left
                .as_f64()
                .is_some_and(|float| float.fract() == 0.0 && float as i128 == integer),
            (None, None) => left.as_f64() == right.as_f64(),
        },
        _ => left == right,
    }
}

fn add_condition_facts(condition: &PolicyCondition, context: &mut BTreeMap<String, Value>) {
    match condition {
        PolicyCondition::All { conditions } => {
            for condition in conditions {
                add_condition_facts(condition, context);
            }
        }
        PolicyCondition::Eq { key, value } => {
            context.entry(key.clone()).or_insert_with(|| value.clone());
        }
        PolicyCondition::In { key, values } if values.len() == 1 => {
            context
                .entry(key.clone())
                .or_insert_with(|| values[0].clone());
        }
        PolicyCondition::Defined { key } => {
            context.entry(key.clone()).or_insert(Value::Bool(true));
        }
        PolicyCondition::Any { .. } | PolicyCondition::Not { .. } | PolicyCondition::In { .. } => {}
    }
}

fn select_evidence_bounded(
    edge: &EdgeRecord,
    requirement: &PolicyEvidenceRequirement,
    evidence: &BTreeMap<(&str, &str), Vec<&EvidenceRecord>>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PolicyEvidenceSpan>> {
    work.step(is_cancelled)?;
    let edge_records = evidence
        .get(&("edge", edge.id.as_str()))
        .map(Vec::as_slice)
        .unwrap_or_default();
    let records = if edge_records.is_empty() {
        edge.site_id.as_deref().map_or(&[][..], |site_id| {
            evidence
                .get(&("site", site_id))
                .map(Vec::as_slice)
                .unwrap_or_default()
        })
    } else {
        edge_records
    };
    let mut records_by_priority = Vec::with_capacity(records.len());
    for record in records {
        work.step(is_cancelled)?;
        records_by_priority.push(*record);
    }
    charge_sort_work(records_by_priority.len(), work, is_cancelled)?;
    records_by_priority.sort_by(|left, right| {
        (
            left.ordinal,
            &left.kind,
            &left.path,
            left.start_line,
            left.start_column,
        )
            .cmp(&(
                right.ordinal,
                &right.kind,
                &right.path,
                right.start_line,
                right.start_column,
            ))
    });
    let mut spans = Vec::new();
    for record in records_by_priority {
        work.step(is_cancelled)?;
        if requirement.primary_only && record.ordinal != 0 {
            continue;
        }
        let kind: EvidenceKind = serde_json::from_value(Value::String(record.kind.clone()))
            .with_context(|| {
                format!(
                    "edge {:?} evidence has unknown kind {:?}",
                    edge.id, record.kind
                )
            })?;
        if !requirement.kinds.contains(&kind) {
            continue;
        }
        spans.push(PolicyEvidenceSpan {
            kind,
            path: record.path.clone(),
            start_line: u32::try_from(record.start_line)?,
            start_column: u32::try_from(record.start_column)?,
            end_line: u32::try_from(record.end_line)?,
            end_column: u32::try_from(record.end_column)?,
        });
    }
    canonicalize_evidence_bounded(&mut spans, work, is_cancelled)?;
    Ok(spans)
}

fn node_policy_evidence(
    index: &NodeEvidenceIndex<'_>,
    node: &NodeRecord,
    requirement: &PolicyEvidenceRequirement,
) -> Result<Vec<PolicyEvidenceSpan>> {
    let records = index
        .records
        .get(node.id.as_str())
        .cloned()
        .unwrap_or_default();

    let mut spans = Vec::new();
    for record in records {
        if requirement.primary_only && record.ordinal != 0 {
            continue;
        }
        let kind: EvidenceKind = serde_json::from_value(Value::String(record.kind.clone()))
            .with_context(|| {
                format!(
                    "node {:?} evidence has unknown kind {:?}",
                    node.id, record.kind
                )
            })?;
        if !requirement.kinds.contains(&kind) {
            continue;
        }
        spans.push(PolicyEvidenceSpan {
            kind,
            path: record.path.clone(),
            start_line: u32::try_from(record.start_line)?,
            start_column: u32::try_from(record.start_column)?,
            end_line: u32::try_from(record.end_line)?,
            end_column: u32::try_from(record.end_column)?,
        });
    }
    if requirement.kinds.contains(&EvidenceKind::Source)
        && let Some(path) = string_property(&node.properties, &["source_path", "path"])
        && let Some(span) = node
            .properties
            .get("source_span")
            .and_then(Value::as_object)
    {
        let position = |name: &str| {
            span.get(name)
                .and_then(Value::as_u64)
                .with_context(|| format!("node {:?} source_span.{name} is missing", node.id))
                .and_then(|value| u32::try_from(value).map_err(Into::into))
        };
        spans.push(PolicyEvidenceSpan {
            kind: EvidenceKind::Source,
            path: path.to_owned(),
            start_line: position("start_line")?,
            start_column: position("start_column")?,
            end_line: position("end_line")?,
            end_column: position("end_column")?,
        });
    }
    canonicalize_evidence(&mut spans);
    Ok(spans)
}

fn append_unique_evidence(
    destination: &mut Vec<PolicyEvidenceSpan>,
    evidence: Vec<PolicyEvidenceSpan>,
) {
    for span in evidence {
        if !destination.contains(&span) {
            destination.push(span);
        }
    }
}

fn canonicalize_evidence(evidence: &mut Vec<PolicyEvidenceSpan>) {
    evidence.sort_by(|left, right| {
        (
            evidence_kind_name(left.kind),
            &left.path,
            left.start_line,
            left.start_column,
            left.end_line,
            left.end_column,
        )
            .cmp(&(
                evidence_kind_name(right.kind),
                &right.path,
                right.start_line,
                right.start_column,
                right.end_line,
                right.end_column,
            ))
    });
    evidence.dedup();
}

fn canonicalize_evidence_bounded(
    evidence: &mut Vec<PolicyEvidenceSpan>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    charge_sort_work(evidence.len(), work, is_cancelled)?;
    work.steps(evidence.len(), is_cancelled)?;
    canonicalize_evidence(evidence);
    Ok(())
}

fn combined_condition(edges: &[&AdmittedEdge<'_>]) -> Result<PolicyCondition> {
    let mut conditions: BTreeMap<String, PolicyCondition> = BTreeMap::new();
    for edge in edges {
        let canonical = canonical_condition(&edge.condition)?;
        conditions.insert(serde_json::to_string(&canonical)?, canonical);
    }
    if conditions.len() == 1 {
        Ok(conditions.into_values().next().expect("one condition"))
    } else {
        canonical_condition(&PolicyCondition::All {
            conditions: conditions.into_values().collect(),
        })
    }
}

fn combined_condition_bounded(
    edges: &[&AdmittedEdge<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyCondition> {
    let mut conditions: BTreeMap<String, PolicyCondition> = BTreeMap::new();
    for edge in edges {
        work.step(is_cancelled)?;
        let canonical = canonical_condition(&edge.condition)?;
        work.step(is_cancelled)?;
        conditions.insert(serde_json::to_string(&canonical)?, canonical);
    }
    work.steps(conditions.len(), is_cancelled)?;
    if conditions.len() == 1 {
        Ok(conditions.into_values().next().expect("one condition"))
    } else {
        canonical_condition(&PolicyCondition::All {
            conditions: conditions.into_values().collect(),
        })
    }
}

fn canonical_condition(condition: &PolicyCondition) -> Result<PolicyCondition> {
    Ok(serde_json::from_value(serde_json::to_value(
        condition.canonicalized(),
    )?)?)
}

fn serialized_names<T: Serialize>(values: &[T]) -> Result<BTreeSet<String>> {
    let mut output = BTreeSet::new();
    for value in values {
        let serialized = serde_json::to_value(value)?;
        let name = serialized
            .as_str()
            .context("policy enum did not serialize as a string")?;
        output.insert(name.to_owned());
    }
    Ok(output)
}

fn path_step(edge: &EdgeRecord) -> PolicyPathStep {
    PolicyPathStep {
        source_id: edge.source.clone(),
        edge_id: edge.id.clone(),
        target_id: edge.target.clone(),
    }
}

fn cycle_level(kind: PolicySelectorKind) -> Option<CycleLevel> {
    match kind {
        PolicySelectorKind::Package => Some(CycleLevel::Package),
        PolicySelectorKind::File => Some(CycleLevel::File),
        PolicySelectorKind::Symbol => Some(CycleLevel::Symbol),
        PolicySelectorKind::Type => Some(CycleLevel::Type),
        PolicySelectorKind::Route => Some(CycleLevel::Route),
        PolicySelectorKind::Component => None,
    }
}

fn evidence_kind_name(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Source => "source",
        EvidenceKind::Semantic => "semantic",
        EvidenceKind::Build => "build",
        EvidenceKind::Runtime => "runtime",
    }
}

fn rule_kind_name(kind: &PolicyRuleKind) -> &'static str {
    match kind {
        PolicyRuleKind::LayerBoundary => "layer-boundary",
        PolicyRuleKind::ForbiddenDependency => "forbidden",
        PolicyRuleKind::Cycle => "cycle",
        PolicyRuleKind::DependencyDepth => "dependency-depth",
        PolicyRuleKind::FanIn => "fan-in",
        PolicyRuleKind::FanOut => "fan-out",
        PolicyRuleKind::PublicApiChange => "public-api-change",
        PolicyRuleKind::RuntimeBoundary => "runtime-boundary",
    }
}

fn public_api_change_kind_name(kind: PublicApiChangeKind) -> &'static str {
    match kind {
        PublicApiChangeKind::Added => "added",
        PublicApiChangeKind::Removed => "removed",
        PublicApiChangeKind::Changed => "changed",
    }
}

#[cfg(test)]
mod tests {
    use depgraph_protocol::{Precision, ResolutionStatus};
    use depgraph_store::{CoverageRecord, ProfileMatrixRecord, ScanRecord};
    use serde_json::json;

    use super::*;
    use crate::policy::{
        POLICY_SCHEMA_VERSION, PolicySelectorPattern, PolicySelectorScope, PolicySeverity,
        PolicySuppressionScope, PolicyThreshold,
    };

    fn node(id: &str, path: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "file".to_owned(),
            locator: format!("file://{path}"),
            display_name: path.to_owned(),
            properties: json!({"path": path, "package_locator": "pkg:fixture"}),
        }
    }

    fn package_node(id: &str, locator: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "package_instance".to_owned(),
            locator: locator.to_owned(),
            display_name: locator.to_owned(),
            properties: json!({"locator": locator}),
        }
    }

    fn semantic_node(id: &str, kind: &str, path: &str, properties: Value) -> NodeRecord {
        let mut base = serde_json::json!({
            "profile_id": "profile:production",
            "source_path": path,
            "source_span": {
                "start_line": 3,
                "start_column": 1,
                "end_line": 3,
                "end_column": 24
            }
        });
        if let (Some(base), Some(properties)) = (base.as_object_mut(), properties.as_object()) {
            base.extend(properties.clone());
        }
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: format!("{kind}:{id}"),
            display_name: id.to_owned(),
            properties: base,
        }
    }

    fn edge(id: &str, source: &str, target: &str, profile: &str) -> EdgeRecord {
        EdgeRecord {
            id: id.to_owned(),
            site_id: Some(format!("site:{id}")),
            source: source.to_owned(),
            target: target.to_owned(),
            kind: "imports".to_owned(),
            phase: "source".to_owned(),
            environment: "server".to_owned(),
            profile_id: profile.to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({"op":"eq","key":"mode","value":"production"}),
            generated: false,
        }
    }

    fn evidence(edge_id: &str, ordinal: i64) -> EvidenceRecord {
        EvidenceRecord {
            owner_type: "edge".to_owned(),
            owner_id: edge_id.to_owned(),
            ordinal,
            kind: "source".to_owned(),
            extractor: "fixture".to_owned(),
            extractor_version: "1".to_owned(),
            path: "src/source.ts".to_owned(),
            start_line: 1,
            start_column: u64::try_from(ordinal + 1).unwrap(),
            end_line: 1,
            end_column: u64::try_from(ordinal + 2).unwrap(),
            detail: None,
            properties: json!({}),
        }
    }

    fn snapshot(edges: Vec<EdgeRecord>) -> GraphSnapshot {
        let evidence = edges.iter().map(|edge| evidence(&edge.id, 0)).collect();
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan:fixture".to_owned(),
                root: "/fixture".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: String::new(),
                completed_at: None,
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: None,
                health_policy_config_digest: None,
                health_analyzer_version: None,
                health_finding_contract_version: None,
            },
            profiles: vec![
                ProfileRecord {
                    id: "profile:production".to_owned(),
                    language: "web".to_owned(),
                    toolchain: None,
                    command: None,
                    target: None,
                    features: Vec::new(),
                    environment: json!({"mode":"production"}),
                    source_revision: None,
                    properties: json!({}),
                    coverage: None,
                },
                ProfileRecord {
                    id: "profile:development".to_owned(),
                    language: "web".to_owned(),
                    toolchain: None,
                    command: None,
                    target: None,
                    features: Vec::new(),
                    environment: json!({"mode":"development"}),
                    source_revision: None,
                    properties: json!({}),
                    coverage: None,
                },
            ],
            nodes: vec![
                node("a", "src/ui/a.ts"),
                node("b", "src/data/b.ts"),
                node("c", "src/data/c.ts"),
                node("d", "src/data/d.ts"),
            ],
            sites: Vec::new(),
            edges,
            evidence,
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: ProfileMatrixRecord::default(),
        }
    }

    fn selector(value: &str) -> PolicySelector {
        PolicySelector {
            kind: PolicySelectorKind::File,
            field: PolicySelectorField::Path,
            match_kind: PolicyMatchKind::Glob,
            value: value.to_owned(),
            cardinality: PolicySelectorCardinality::Many,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        }
    }

    fn rule(kind: PolicyRuleKind) -> PolicyRule {
        PolicyRule {
            id: "fixture-rule".to_owned(),
            kind,
            severity: PolicySeverity::Error,
            source: selector("src/ui/**"),
            target: selector("src/data/**"),
            profiles: PolicyProfileFilter {
                include: vec![PolicyPattern {
                    match_kind: PolicyMatchKind::Exact,
                    value: "profile:production".to_owned(),
                }],
                exclude: Vec::new(),
            },
            condition: PolicyCondition::Eq {
                key: "mode".to_owned(),
                value: json!("production"),
            },
            precisions: vec![Precision::Exact],
            resolution_statuses: vec![ResolutionStatus::Resolved],
            evidence: PolicyEvidenceRequirement {
                kinds: vec![EvidenceKind::Source],
                minimum_spans: 1,
                primary_only: true,
            },
            threshold: None,
        }
    }

    fn config(rule: PolicyRule) -> PolicyConfig {
        PolicyConfig {
            schema_version: POLICY_SCHEMA_VERSION.to_owned(),
            rules: vec![rule],
            suppressions: Vec::new(),
        }
    }

    fn runtime_boundary_broad_fixture(
        source_count: usize,
        chain_length: usize,
    ) -> (GraphSnapshot, PolicyConfig) {
        assert!(source_count > 0);
        assert!(chain_length > 0);

        let mut nodes = Vec::with_capacity(source_count + chain_length + 1);
        for index in 0..source_count {
            let id = format!("source-{index:04}");
            nodes.push(semantic_node(
                &id,
                "component",
                &format!("src/{id}.tsx"),
                json!({}),
            ));
        }
        for index in 0..chain_length {
            let id = format!("chain-{index:04}");
            nodes.push(semantic_node(
                &id,
                "component",
                &format!("src/{id}.tsx"),
                json!({}),
            ));
        }
        nodes.push(semantic_node(
            "boundary",
            "component",
            "src/boundary.tsx",
            json!({}),
        ));

        let mut edges = Vec::with_capacity(source_count + chain_length);
        for index in 0..source_count {
            let source = format!("source-{index:04}");
            edges.push(edge(
                &format!("{source}-imports-chain"),
                &source,
                "chain-0000",
                "profile:production",
            ));
        }
        for index in 0..chain_length.saturating_sub(1) {
            let source = format!("chain-{index:04}");
            let target = format!("chain-{:04}", index + 1);
            edges.push(edge(
                &format!("{source}-imports-next"),
                &source,
                &target,
                "profile:production",
            ));
        }
        let mut boundary_edge = edge(
            "chain-crosses-boundary",
            &format!("chain-{:04}", chain_length - 1),
            "boundary",
            "profile:production",
        );
        boundary_edge.kind = "client_boundary".to_owned();
        edges.push(boundary_edge);

        let mut graph = snapshot(edges);
        graph.nodes = nodes;

        let mut runtime = rule(PolicyRuleKind::RuntimeBoundary);
        runtime.id = "bounded-runtime-boundary".to_owned();
        runtime.source = PolicySelector {
            kind: PolicySelectorKind::Component,
            field: PolicySelectorField::Locator,
            match_kind: PolicyMatchKind::Prefix,
            value: "component:source-".to_owned(),
            cardinality: PolicySelectorCardinality::Many,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        runtime.target = PolicySelector {
            kind: PolicySelectorKind::Component,
            field: PolicySelectorField::Locator,
            match_kind: PolicyMatchKind::Exact,
            value: "component:boundary".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        (graph, config(runtime))
    }

    #[test]
    fn runtime_boundary_broad_selector_honors_work_budget_and_cancellation() -> Result<()> {
        let (graph, policy) = runtime_boundary_broad_fixture(64, 128);

        let exhausted =
            evaluate_policy_cancellable("snapshot:bounded-runtime", &graph, &policy, 2_000, || {
                false
            })
            .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut checks = 0;
        let cancelled = evaluate_policy_cancellable(
            "snapshot:bounded-runtime",
            &graph,
            &policy,
            usize::MAX,
            || {
                checks += 1;
                checks > 2_000
            },
        )
        .unwrap_err();
        assert!(is_policy_evaluation_cancelled(&cancelled));
        assert_eq!(checks, 2_001);
        Ok(())
    }

    #[test]
    fn runtime_boundary_preprocessing_and_materialization_are_bounded() -> Result<()> {
        let mut graph = snapshot(vec![
            edge("e1", "a", "b", "profile:production"),
            edge("e2", "a", "c", "profile:production"),
        ]);
        graph.evidence.push(evidence("e1", 1));
        let runtime = rule(PolicyRuleKind::RuntimeBoundary);
        let admitted = admitted_edges_with_options(&graph, &runtime, false, true)?;
        let admitted_refs = admitted.iter().collect::<Vec<_>>();

        // Each insertion and ordered-map lookup has an exact allowance: the
        // following deterministic outgoing-edge sort must consume more work.
        let adjacency_insertion_work = admitted_refs.len().saturating_mul(2);
        let mut work = PolicyEvaluationWork::new(adjacency_insertion_work);
        let exhausted = adjacency_bounded(&admitted_refs, &mut work, &mut || false).unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut evidence_by_owner: BTreeMap<(&str, &str), Vec<&EvidenceRecord>> = BTreeMap::new();
        for item in &graph.evidence {
            evidence_by_owner
                .entry((item.owner_type.as_str(), item.owner_id.as_str()))
                .or_default()
                .push(item);
        }
        // Selection plus two reference copies consume three units; sorting
        // the two records is separately budgeted.
        let mut work = PolicyEvaluationWork::new(3);
        let exhausted = select_evidence_bounded(
            &graph.edges[0],
            &runtime.evidence,
            &evidence_by_owner,
            &mut work,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let nodes = graph
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<BTreeMap<_, _>>();
        // Two node lookups and one path-edge visit consume three units. The
        // evidence clone performed while materializing the violation must be
        // charged next rather than escaping the shared RuntimeBoundary limit.
        let mut work = PolicyEvaluationWork::new(3);
        let exhausted = make_violation_bounded(
            &runtime,
            &nodes,
            "a",
            "b",
            Some("profile:production"),
            vec![path_step(admitted[0].edge)],
            vec![&admitted[0]],
            "bounded fixture".to_owned(),
            &[],
            &mut work,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let cancelled = adjacency_bounded(&admitted_refs, &mut work, &mut || true).unwrap_err();
        assert!(is_policy_evaluation_cancelled(&cancelled));
        Ok(())
    }

    #[test]
    fn runtime_boundary_suppression_selector_honors_work_budget_and_cancellation() -> Result<()> {
        let (graph, mut policy) = runtime_boundary_broad_fixture(64, 128);
        policy.suppressions.push(PolicySuppression {
            id: "bounded-suppression".to_owned(),
            rule_id: "bounded-runtime-boundary".to_owned(),
            reason: "fixture suppression".to_owned(),
            scope: PolicySuppressionScope {
                source: Some(policy.rules[0].source.clone()),
                ..PolicySuppressionScope::default()
            },
        });

        let mut checks = 0;
        let mut work = PolicyEvaluationWork::new(1);
        let exhausted = resolve_suppressions_bounded(
            &graph,
            &policy,
            Some("bounded-runtime-boundary"),
            &mut work,
            &mut || {
                checks += 1;
                false
            },
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));
        assert_eq!(checks, 2);

        let mut checks = 0;
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let cancelled = resolve_suppressions_bounded(
            &graph,
            &policy,
            Some("bounded-runtime-boundary"),
            &mut work,
            &mut || {
                checks += 1;
                checks > 1
            },
        )
        .unwrap_err();
        assert!(is_policy_evaluation_cancelled(&cancelled));
        assert_eq!(checks, 2);
        Ok(())
    }

    #[test]
    fn bounded_selector_charges_scope_and_exclusion_patterns() -> Result<()> {
        let (graph, policy) = runtime_boundary_broad_fixture(1, 1);
        let mut node = graph.nodes[0].clone();
        node.properties = json!({"path": "src/source-0000.tsx"});

        let mut scoped_selector = policy.rules[0].source.clone();
        scoped_selector.scope.paths = vec![
            PolicyPattern {
                match_kind: PolicyMatchKind::Exact,
                value: "src/does-not-exist.tsx".to_owned(),
            },
            PolicyPattern {
                match_kind: PolicyMatchKind::Exact,
                value: "src/also-does-not-exist.tsx".to_owned(),
            },
        ];
        let mut work = PolicyEvaluationWork::new(1);
        let exhausted =
            selector_matches_node_bounded(&node, &scoped_selector, &mut work, &mut || false)
                .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut excluded_selector = policy.rules[0].source.clone();
        excluded_selector.exclude = (0..3)
            .map(|index| PolicySelectorPattern {
                field: PolicySelectorField::Locator,
                match_kind: PolicyMatchKind::Exact,
                value: format!("component:does-not-exist-{index}"),
            })
            .collect();
        let mut work = PolicyEvaluationWork::new(2);
        let exhausted =
            selector_matches_node_bounded(&node, &excluded_selector, &mut work, &mut || false)
                .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut checks = 0;
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let cancelled =
            selector_matches_node_bounded(&node, &excluded_selector, &mut work, &mut || {
                checks += 1;
                checks > 2
            })
            .unwrap_err();
        assert!(is_policy_evaluation_cancelled(&cancelled));
        assert_eq!(checks, 3);
        Ok(())
    }

    #[test]
    fn runtime_boundary_audit_shares_one_work_budget_across_snapshots() -> Result<()> {
        let (before, policy) = runtime_boundary_broad_fixture(8, 16);
        let mut one_snapshot_work: usize = 0;
        let one_snapshot =
            evaluate_policy_cancellable("snapshot:before", &before, &policy, usize::MAX, || {
                one_snapshot_work += 1;
                false
            })?;
        assert!(!one_snapshot.violations.is_empty());
        assert!(one_snapshot_work > 1);

        let single_snapshot_budget = one_snapshot_work.saturating_add(1);
        let after = before.clone();
        evaluate_policy_cancellable(
            "snapshot:before",
            &before,
            &policy,
            single_snapshot_budget,
            || false,
        )?;
        let exhausted = evaluate_boundary_violation_ids_cancellable(
            "snapshot:before",
            &before,
            "snapshot:after",
            &after,
            &policy,
            single_snapshot_budget,
            || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut measurement = PolicyEvaluationWork::new(usize::MAX);
        let before_result = evaluate_policy_with_work(
            "snapshot:before",
            &before,
            &policy,
            &mut measurement,
            &mut || false,
        )?;
        let after_result = evaluate_policy_diff_with_work(
            "snapshot:before",
            &before,
            "snapshot:after",
            &after,
            &policy,
            &mut measurement,
            &mut || false,
        )?;
        let evaluation_work = measurement.used;

        let mut exact_evaluation_budget = PolicyEvaluationWork::new(evaluation_work);
        let repeated_before = evaluate_policy_with_work(
            "snapshot:before",
            &before,
            &policy,
            &mut exact_evaluation_budget,
            &mut || false,
        )?;
        let repeated_after = evaluate_policy_diff_with_work(
            "snapshot:before",
            &before,
            "snapshot:after",
            &after,
            &policy,
            &mut exact_evaluation_budget,
            &mut || false,
        )?;
        assert_eq!(repeated_before, before_result);
        assert_eq!(repeated_after, after_result);
        assert_eq!(exact_evaluation_budget.used, evaluation_work);
        let exhausted = new_boundary_violation_ids_bounded(
            &repeated_before,
            &repeated_after,
            &policy,
            &mut exact_evaluation_budget,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut comparison_work = PolicyEvaluationWork::new(usize::MAX);
        let cancelled = new_boundary_violation_ids_bounded(
            &before_result,
            &after_result,
            &policy,
            &mut comparison_work,
            &mut || true,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_cancelled(&cancelled));
        Ok(())
    }

    #[test]
    fn boundary_audit_filters_non_boundary_rules_and_their_suppressions() -> Result<()> {
        let (graph, mut policy) = runtime_boundary_broad_fixture(1, 1);
        let mut cycle = rule(PolicyRuleKind::Cycle);
        cycle.id = "unrelated-cycle".to_owned();
        policy.suppressions.push(PolicySuppression {
            id: "unrelated-cycle-suppression".to_owned(),
            rule_id: cycle.id.clone(),
            reason: "not part of a health boundary audit".to_owned(),
            scope: PolicySuppressionScope {
                source: Some(cycle.source.clone()),
                ..PolicySuppressionScope::default()
            },
        });
        policy.rules.push(cycle);

        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let filtered = boundary_policy_config_bounded(&policy, &mut work, &mut || false)?;
        assert_eq!(filtered.rules.len(), 1);
        assert_eq!(filtered.rules[0].kind, PolicyRuleKind::RuntimeBoundary);
        assert!(filtered.suppressions.is_empty());

        let ids = evaluate_boundary_violation_ids_cancellable(
            "snapshot:before",
            &graph,
            "snapshot:after",
            &graph,
            &policy,
            usize::MAX,
            || false,
        )?;
        assert!(ids.is_empty());
        Ok(())
    }

    #[test]
    fn forbidden_dependency_respects_profile_condition_precision_and_evidence() -> Result<()> {
        let production = edge("e1", "a", "b", "profile:production");
        let mut development = edge("e2", "a", "c", "profile:development");
        development.condition = json!({"op":"eq","key":"mode","value":"development"});
        let mut candidate = edge("e3", "a", "d", "profile:production");
        candidate.precision = "heuristic".to_owned();
        candidate.resolution_status = "candidates".to_owned();
        let graph = snapshot(vec![candidate, development, production]);

        let result = evaluate_policy(
            "snapshot:fixture",
            &graph,
            &config(rule(PolicyRuleKind::ForbiddenDependency)),
        )?;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].dependency_path[0].edge_id, "e1");
        assert_eq!(
            result.violations[0].profile_id.as_deref(),
            Some("profile:production")
        );
        assert_eq!(result.exit_code, 1);
        Ok(())
    }

    #[test]
    fn specialized_rules_do_not_discard_snapshot_policy_results() -> Result<()> {
        let graph = snapshot(vec![edge("e1", "a", "b", "profile:production")]);
        let static_rule = rule(PolicyRuleKind::ForbiddenDependency);
        let mut specialized_rule = rule(PolicyRuleKind::PublicApiChange);
        specialized_rule.id = "public-api".to_owned();
        specialized_rule.source.value = "not-present/**".to_owned();
        specialized_rule.target = PolicySelector {
            kind: PolicySelectorKind::Symbol,
            field: PolicySelectorField::Locator,
            match_kind: PolicyMatchKind::Prefix,
            value: "symbol:".to_owned(),
            cardinality: PolicySelectorCardinality::Many,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        let policy = PolicyConfig {
            schema_version: POLICY_SCHEMA_VERSION.to_owned(),
            rules: vec![specialized_rule, static_rule],
            suppressions: Vec::new(),
        };

        let result = evaluate_policy("snapshot:fixture", &graph, &policy)?;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].rule_id, "fixture-rule");
        assert_eq!(result.exit_code, 1);
        Ok(())
    }

    #[test]
    fn boundary_violation_ids_are_taken_from_policy_evaluator_results() -> Result<()> {
        let graph = snapshot(vec![edge("e1", "a", "b", "profile:production")]);
        let policy = config(rule(PolicyRuleKind::ForbiddenDependency));
        let result = evaluate_policy("snapshot:fixture", &graph, &policy)?;
        assert_eq!(result.violations.len(), 1);

        let empty = PolicyResult::new("snapshot:empty", Vec::new());
        let ids = new_boundary_violation_ids(&empty, &result, &policy);
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&result.violations[0].id));
        assert!(
            result.violations[0]
                .id
                .starts_with("policy-violation:sha256:")
        );

        let moved_edge = evaluate_policy(
            "snapshot:moved-edge",
            &snapshot(vec![edge("e2", "a", "b", "profile:production")]),
            &policy,
        )?;
        assert_ne!(result.violations[0].id, moved_edge.violations[0].id);
        assert!(new_boundary_violation_ids(&result, &moved_edge, &policy).is_empty());

        let added_parallel_edge = evaluate_policy(
            "snapshot:parallel-edge",
            &snapshot(vec![
                edge("e2", "a", "b", "profile:production"),
                edge("e3", "a", "b", "profile:production"),
            ]),
            &policy,
        )?;
        let added_edge_id = added_parallel_edge
            .violations
            .iter()
            .find(|violation| violation.dependency_path[0].edge_id == "e3")
            .expect("parallel edge e3 violation")
            .id
            .clone();
        assert_eq!(
            new_boundary_violation_ids(&moved_edge, &added_parallel_edge, &policy),
            BTreeSet::from([added_edge_id])
        );

        let all_after_ids = added_parallel_edge
            .violations
            .iter()
            .map(|violation| violation.id.clone())
            .collect::<BTreeSet<_>>();
        let moved_and_added = new_boundary_violation_ids(&result, &added_parallel_edge, &policy);
        assert_eq!(moved_and_added.len(), 1);
        assert!(moved_and_added.is_subset(&all_after_ids));

        let new_target = evaluate_policy(
            "snapshot:new-target",
            &snapshot(vec![edge("e3", "a", "c", "profile:production")]),
            &policy,
        )?;
        assert_eq!(
            new_boundary_violation_ids(&result, &new_target, &policy),
            BTreeSet::from([new_target.violations[0].id.clone()])
        );

        let mut suppressed_policy = policy;
        suppressed_policy.suppressions.push(PolicySuppression {
            id: "reviewed-boundary".to_owned(),
            rule_id: "fixture-rule".to_owned(),
            reason: "accepted architecture exception".to_owned(),
            scope: PolicySuppressionScope {
                source: Some(PolicySelector {
                    match_kind: PolicyMatchKind::Exact,
                    value: "src/ui/a.ts".to_owned(),
                    cardinality: PolicySelectorCardinality::One,
                    ..selector("unused")
                }),
                ..PolicySuppressionScope::default()
            },
        });
        let suppressed = evaluate_policy("snapshot:fixture", &graph, &suppressed_policy)?;
        assert_eq!(suppressed.summary.suppressed, 1);
        assert!(new_boundary_violation_ids(&empty, &suppressed, &suppressed_policy).is_empty());
        Ok(())
    }

    #[test]
    fn runtime_boundary_links_route_path_profile_condition_and_exit_behavior() -> Result<()> {
        let mut route_to_server = edge(
            "route-renders-server",
            "route",
            "server-component",
            "profile:production",
        );
        route_to_server.kind = "renders".to_owned();
        let mut server_to_client = edge(
            "server-crosses-client",
            "server-component",
            "client-component",
            "profile:production",
        );
        server_to_client.kind = "client_boundary".to_owned();
        server_to_client.condition = json!({
            "op": "all",
            "conditions": [
                {"op":"eq","key":"mode","value":"production"},
                {"op":"eq","key":"next.boundary","value":"client"},
                {"op":"eq","key":"next.runtime","value":"edge"}
            ]
        });
        let mut graph = snapshot(vec![server_to_client, route_to_server]);
        graph.nodes = vec![
            semantic_node(
                "route",
                "route",
                "app/page.tsx",
                json!({"environment":"server"}),
            ),
            semantic_node(
                "server-component",
                "component",
                "app/page.tsx",
                json!({"environment":"server"}),
            ),
            semantic_node(
                "client-component",
                "component",
                "app/client.tsx",
                json!({"environment":"browser"}),
            ),
        ];
        let mut runtime = rule(PolicyRuleKind::RuntimeBoundary);
        runtime.id = "no-edge-client".to_owned();
        runtime.source = PolicySelector {
            kind: PolicySelectorKind::Route,
            field: PolicySelectorField::Id,
            match_kind: PolicyMatchKind::Exact,
            value: "route".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        runtime.target = PolicySelector {
            kind: PolicySelectorKind::Component,
            field: PolicySelectorField::Id,
            match_kind: PolicyMatchKind::Exact,
            value: "client-component".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        runtime.condition = PolicyCondition::Eq {
            key: "next.runtime".to_owned(),
            value: json!("edge"),
        };

        let active = evaluate_policy("snapshot:runtime", &graph, &config(runtime.clone()))?;
        assert_eq!(active.exit_code, 1);
        assert_eq!(active.violations.len(), 1);
        assert_eq!(
            active.violations[0]
                .dependency_path
                .iter()
                .map(|step| step.edge_id.as_str())
                .collect::<Vec<_>>(),
            vec!["route-renders-server", "server-crosses-client"]
        );
        assert_eq!(
            active.violations[0].profile_id.as_deref(),
            Some("profile:production")
        );
        assert!(serde_json::to_string(&active.violations[0].condition)?.contains("next.runtime"));
        let mut server_boundary_graph = graph.clone();
        server_boundary_graph
            .edges
            .iter_mut()
            .find(|edge| edge.id == "server-crosses-client")
            .context("boundary edge")?
            .kind = "server_boundary".to_owned();
        let server_boundary = evaluate_policy(
            "snapshot:runtime-server",
            &server_boundary_graph,
            &config(runtime.clone()),
        )?;
        assert_eq!(server_boundary.violations.len(), 1);
        assert!(
            server_boundary.violations[0]
                .message
                .contains("server_boundary")
        );

        runtime.severity = PolicySeverity::Warning;
        let warning = evaluate_policy("snapshot:runtime", &graph, &config(runtime.clone()))?;
        assert_eq!(warning.summary.warnings, 1);
        assert_eq!(warning.exit_code, 0);

        runtime.severity = PolicySeverity::Error;
        let mut suppressed_config = config(runtime);
        suppressed_config.suppressions.push(PolicySuppression {
            id: "allow-client-island".to_owned(),
            rule_id: "no-edge-client".to_owned(),
            reason: "reviewed migration".to_owned(),
            scope: PolicySuppressionScope {
                target: Some(PolicySelector {
                    kind: PolicySelectorKind::Component,
                    field: PolicySelectorField::Id,
                    match_kind: PolicyMatchKind::Exact,
                    value: "client-component".to_owned(),
                    cardinality: PolicySelectorCardinality::One,
                    exclude: Vec::new(),
                    scope: PolicySelectorScope::default(),
                }),
                ..PolicySuppressionScope::default()
            },
        });
        let suppressed = evaluate_policy("snapshot:runtime", &graph, &suppressed_config)?;
        assert_eq!(suppressed.summary.suppressed, 1);
        assert_eq!(suppressed.exit_code, 0);
        Ok(())
    }

    #[test]
    fn public_api_diff_classifies_changes_and_links_impact_evidence() -> Result<()> {
        let consumer = semantic_node(
            "consumer",
            "symbol",
            "src/consumer.ts",
            json!({"signature":"consumer-v1"}),
        );
        let api_v1 = semantic_node(
            "public-api",
            "symbol",
            "src/public.ts",
            json!({"signature":"v1"}),
        );
        let api_v2 = semantic_node(
            "public-api",
            "symbol",
            "src/public.ts",
            json!({"signature":"v2"}),
        );
        let dependency = edge(
            "consumer-imports-api",
            "consumer",
            "public-api",
            "profile:production",
        );
        let mut baseline = snapshot(vec![dependency.clone()]);
        baseline.nodes = vec![api_v1.clone(), consumer.clone()];
        let mut changed = snapshot(vec![dependency]);
        changed.nodes = vec![consumer.clone(), api_v2];
        let mut removed = snapshot(Vec::new());
        removed.nodes = vec![consumer.clone()];
        let mut before_added = snapshot(Vec::new());
        before_added.nodes = vec![consumer.clone()];
        let mut after_added = snapshot(Vec::new());
        after_added.nodes = vec![consumer, api_v1];

        let mut public_rule = rule(PolicyRuleKind::PublicApiChange);
        public_rule.id = "stable-public-api".to_owned();
        public_rule.source = PolicySelector {
            kind: PolicySelectorKind::Symbol,
            field: PolicySelectorField::Id,
            match_kind: PolicyMatchKind::Exact,
            value: "consumer".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        public_rule.target = PolicySelector {
            kind: PolicySelectorKind::Symbol,
            field: PolicySelectorField::Id,
            match_kind: PolicyMatchKind::Exact,
            value: "public-api".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        public_rule.condition = PolicyCondition::default();
        let policy = config(public_rule.clone());

        let changed_result =
            evaluate_policy_diff("baseline", &baseline, "changed", &changed, &policy)?;
        assert_eq!(changed_result.api_changes.len(), 1);
        assert_eq!(
            changed_result.api_changes[0].kind,
            PublicApiChangeKind::Changed
        );
        assert!(changed_result.api_changes[0].breaking);
        assert_eq!(changed_result.violations.len(), 1);
        assert_eq!(
            changed_result.violations[0].change_id.as_deref(),
            Some(changed_result.api_changes[0].id.as_str())
        );
        assert_eq!(
            changed_result.violations[0].dependency_path[0].edge_id,
            "consumer-imports-api"
        );
        assert_eq!(
            changed_result.violations[0].evidence[0].path,
            "src/public.ts"
        );
        assert_eq!(changed_result.exit_code, 1);

        let removed_result =
            evaluate_policy_diff("baseline", &baseline, "removed", &removed, &policy)?;
        assert_eq!(
            removed_result.api_changes[0].kind,
            PublicApiChangeKind::Removed
        );
        assert_eq!(removed_result.violations.len(), 1);
        assert_eq!(removed_result.exit_code, 1);

        let added_result = evaluate_policy_diff(
            "before-added",
            &before_added,
            "after-added",
            &after_added,
            &policy,
        )?;
        assert_eq!(added_result.api_changes[0].kind, PublicApiChangeKind::Added);
        assert!(!added_result.api_changes[0].breaking);
        assert!(added_result.violations.is_empty());
        assert_eq!(added_result.exit_code, 0);

        public_rule.severity = PolicySeverity::Warning;
        let warning = evaluate_policy_diff(
            "baseline",
            &baseline,
            "changed",
            &changed,
            &config(public_rule.clone()),
        )?;
        assert_eq!(warning.summary.warnings, 1);
        assert_eq!(warning.exit_code, 0);

        let mut suppressed_policy = config(public_rule);
        suppressed_policy.rules[0].severity = PolicySeverity::Error;
        suppressed_policy.suppressions.push(PolicySuppression {
            id: "allow-api-change".to_owned(),
            rule_id: "stable-public-api".to_owned(),
            reason: "versioned rollout".to_owned(),
            scope: PolicySuppressionScope {
                target: Some(PolicySelector {
                    kind: PolicySelectorKind::Symbol,
                    field: PolicySelectorField::Id,
                    match_kind: PolicyMatchKind::Exact,
                    value: "public-api".to_owned(),
                    cardinality: PolicySelectorCardinality::One,
                    exclude: Vec::new(),
                    scope: PolicySelectorScope::default(),
                }),
                ..PolicySuppressionScope::default()
            },
        });
        let suppressed = evaluate_policy_diff(
            "baseline",
            &baseline,
            "changed",
            &changed,
            &suppressed_policy,
        )?;
        assert_eq!(suppressed.summary.suppressed, 1);
        assert_eq!(suppressed.exit_code, 0);
        Ok(())
    }

    #[test]
    fn public_api_diff_uses_baseline_profile_and_current_properties() -> Result<()> {
        let consumer = semantic_node(
            "consumer",
            "symbol",
            "src/consumer.ts",
            json!({"signature":"consumer-v1"}),
        );
        let api_v1 = semantic_node(
            "public-api",
            "symbol",
            "z/public.ts",
            json!({"signature":"v1","legacy_only":true}),
        );
        let api_v2 = semantic_node(
            "public-api",
            "symbol",
            "z/public.ts",
            json!({"signature":"v2","profile_id":"profile:development"}),
        );
        let dependency = edge(
            "consumer-imports-api",
            "consumer",
            "public-api",
            "profile:production",
        );
        let mut baseline = snapshot(vec![dependency.clone()]);
        baseline.nodes = vec![api_v1, consumer.clone()];
        let mut changed = snapshot(vec![dependency]);
        changed.nodes = vec![api_v2, consumer];

        let mut public_rule = rule(PolicyRuleKind::PublicApiChange);
        public_rule.id = "stable-public-api".to_owned();
        public_rule.source = PolicySelector {
            kind: PolicySelectorKind::Symbol,
            field: PolicySelectorField::Id,
            match_kind: PolicyMatchKind::Exact,
            value: "consumer".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        public_rule.target = PolicySelector {
            kind: PolicySelectorKind::Symbol,
            field: PolicySelectorField::Id,
            match_kind: PolicyMatchKind::Exact,
            value: "public-api".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        public_rule.profiles = PolicyProfileFilter::default();
        public_rule.condition = PolicyCondition::Not {
            condition: Box::new(PolicyCondition::Defined {
                key: "legacy_only".to_owned(),
            }),
        };

        let result = evaluate_policy_diff(
            "baseline",
            &baseline,
            "changed-profile",
            &changed,
            &config(public_rule),
        )?;

        assert_eq!(result.api_changes.len(), 1);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].profile_id.as_deref(),
            Some("profile:production")
        );
        assert_eq!(
            result.violations[0]
                .evidence
                .iter()
                .map(|span| span.path.as_str())
                .collect::<Vec<_>>(),
            vec!["src/source.ts", "z/public.ts"]
        );
        Ok(())
    }

    #[test]
    fn diff_suppression_follows_confirmed_rename_identity() -> Result<()> {
        let old_api = semantic_node(
            "public-api-v1",
            "symbol",
            "src/public.ts",
            json!({"signature":"v1"}),
        );
        let new_api = semantic_node(
            "public-api-v2",
            "symbol",
            "src/public.ts",
            json!({"signature":"v2"}),
        );
        let mut from = snapshot(Vec::new());
        from.nodes = vec![old_api];
        let mut to = snapshot(Vec::new());
        to.nodes = vec![new_api];
        let mut policy = config(rule(PolicyRuleKind::PublicApiChange));
        policy.suppressions.push(PolicySuppression {
            id: "allow-renamed-api".to_owned(),
            rule_id: "fixture-rule".to_owned(),
            reason: "versioned migration".to_owned(),
            scope: PolicySuppressionScope {
                target: Some(PolicySelector {
                    kind: PolicySelectorKind::Symbol,
                    field: PolicySelectorField::Id,
                    match_kind: PolicyMatchKind::Exact,
                    value: "public-api-v2".to_owned(),
                    cardinality: PolicySelectorCardinality::One,
                    exclude: Vec::new(),
                    scope: PolicySelectorScope::default(),
                }),
                ..PolicySuppressionScope::default()
            },
        });
        let rename_pairs = [("public-api-v1", "public-api-v2")];

        let suppressions =
            resolve_diff_suppressions(&from, &to, &rename_pairs, &policy, "fixture-rule")?;
        let applied = applied_suppression(
            &suppressions,
            "fixture-rule",
            "consumer",
            "public-api-v1",
            Some("profile:production"),
            &BTreeMap::new(),
        );

        assert_eq!(
            applied.as_ref().map(|value| value.id.as_str()),
            Some("allow-renamed-api")
        );
        Ok(())
    }

    #[test]
    fn suppression_is_applied_without_hiding_the_violation() -> Result<()> {
        let graph = snapshot(vec![edge("e1", "a", "b", "profile:production")]);
        let mut policy = config(rule(PolicyRuleKind::LayerBoundary));
        policy.suppressions.push(PolicySuppression {
            id: "legacy-a".to_owned(),
            rule_id: "fixture-rule".to_owned(),
            reason: "scheduled migration".to_owned(),
            scope: PolicySuppressionScope {
                source: Some(PolicySelector {
                    match_kind: PolicyMatchKind::Exact,
                    value: "src/ui/a.ts".to_owned(),
                    cardinality: PolicySelectorCardinality::One,
                    ..selector("unused")
                }),
                ..PolicySuppressionScope::default()
            },
        });

        let result = evaluate_policy("snapshot:fixture", &graph, &policy)?;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0]
                .suppression
                .as_ref()
                .map(|value| value.id.as_str()),
            Some("legacy-a")
        );
        assert_eq!(result.summary.suppressed, 1);
        assert_eq!(result.exit_code, 0);
        Ok(())
    }

    #[test]
    fn fan_out_depth_and_cycle_thresholds_are_deterministic() -> Result<()> {
        let graph = snapshot(vec![
            edge("e3", "c", "a", "profile:production"),
            edge("e2", "b", "c", "profile:production"),
            edge("e1", "a", "b", "profile:production"),
            edge("e4", "a", "d", "profile:production"),
        ]);

        let mut fan_out = rule(PolicyRuleKind::FanOut);
        fan_out.target = selector("src/**");
        fan_out.threshold = Some(PolicyThreshold { max: 1 });
        let fan_out_result = evaluate_policy("snapshot:fixture", &graph, &config(fan_out))?;
        assert_eq!(fan_out_result.violations.len(), 1);
        assert_eq!(fan_out_result.violations[0].target.id, "d");

        let mut depth = rule(PolicyRuleKind::DependencyDepth);
        depth.target = PolicySelector {
            match_kind: PolicyMatchKind::Exact,
            value: "src/data/c.ts".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            ..selector("unused")
        };
        depth.threshold = Some(PolicyThreshold { max: 1 });
        let depth_result = evaluate_policy("snapshot:fixture", &graph, &config(depth))?;
        assert_eq!(
            depth_result.violations[0]
                .dependency_path
                .iter()
                .map(|step| step.edge_id.as_str())
                .collect::<Vec<_>>(),
            vec!["e1", "e2"]
        );

        let mut cycle_rule = rule(PolicyRuleKind::Cycle);
        cycle_rule.source = selector("src/**");
        cycle_rule.target = selector("src/**");
        cycle_rule.condition = PolicyCondition::default();
        let cycle_result = evaluate_policy("snapshot:fixture", &graph, &config(cycle_rule))?;
        assert_eq!(cycle_result.violations.len(), 1);
        assert_eq!(cycle_result.violations[0].source.id, "a");
        assert_eq!(cycle_result.violations[0].target.id, "a");
        assert_eq!(
            cycle_result.violations[0]
                .dependency_path
                .iter()
                .map(|step| step.edge_id.as_str())
                .collect::<Vec<_>>(),
            vec!["e1", "e2", "e3"]
        );
        Ok(())
    }

    #[test]
    fn fan_in_reports_the_canonical_overflow_source() -> Result<()> {
        let graph = snapshot(vec![
            edge("e3", "c", "d", "profile:production"),
            edge("e1", "a", "d", "profile:production"),
            edge("e2", "b", "d", "profile:production"),
        ]);
        let mut fan_in = rule(PolicyRuleKind::FanIn);
        fan_in.source = selector("src/**");
        fan_in.target = PolicySelector {
            match_kind: PolicyMatchKind::Exact,
            value: "src/data/d.ts".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            ..selector("unused")
        };
        fan_in.threshold = Some(PolicyThreshold { max: 2 });

        let result = evaluate_policy("snapshot:fixture", &graph, &config(fan_in))?;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].source.id, "c");
        assert_eq!(result.violations[0].target.id, "d");
        Ok(())
    }

    #[test]
    fn asymmetric_cycle_selectors_evaluate_their_union_subgraph() -> Result<()> {
        let graph = snapshot(vec![
            edge("e2", "b", "a", "profile:production"),
            edge("e1", "a", "b", "profile:production"),
        ]);
        let mut cycle_rule = rule(PolicyRuleKind::Cycle);
        cycle_rule.condition = PolicyCondition::default();
        cycle_rule.source = PolicySelector {
            match_kind: PolicyMatchKind::Exact,
            value: "src/ui/a.ts".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            ..selector("unused")
        };
        cycle_rule.target = PolicySelector {
            match_kind: PolicyMatchKind::Exact,
            value: "src/data/b.ts".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            ..selector("unused")
        };

        let result = evaluate_policy("snapshot:fixture", &graph, &config(cycle_rule))?;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0]
                .dependency_path
                .iter()
                .map(|step| step.edge_id.as_str())
                .collect::<Vec<_>>(),
            vec!["e1", "e2"]
        );
        Ok(())
    }

    #[test]
    fn candidate_heuristic_edges_are_included_only_when_declared() -> Result<()> {
        let mut candidate = edge("candidate", "a", "b", "profile:production");
        candidate.precision = "heuristic".to_owned();
        candidate.resolution_status = "candidates".to_owned();
        let graph = snapshot(vec![candidate]);
        let mut candidate_rule = rule(PolicyRuleKind::ForbiddenDependency);
        candidate_rule.precisions = vec![Precision::Heuristic];
        candidate_rule.resolution_statuses = vec![ResolutionStatus::Candidates];

        let result = evaluate_policy("snapshot:fixture", &graph, &config(candidate_rule))?;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].dependency_path[0].edge_id, "candidate");
        Ok(())
    }

    #[test]
    fn package_layer_boundary_uses_package_instance_edges() -> Result<()> {
        let mut graph = snapshot(vec![edge(
            "package-edge",
            "package:web",
            "package:data",
            "profile:production",
        )]);
        graph.nodes = vec![
            package_node("package:web", "pkg:web"),
            package_node("package:data", "pkg:data"),
        ];
        let mut package_rule = rule(PolicyRuleKind::LayerBoundary);
        package_rule.condition = PolicyCondition::default();
        package_rule.source = PolicySelector {
            kind: PolicySelectorKind::Package,
            field: PolicySelectorField::Locator,
            match_kind: PolicyMatchKind::Exact,
            value: "pkg:web".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        package_rule.target = PolicySelector {
            kind: PolicySelectorKind::Package,
            field: PolicySelectorField::Locator,
            match_kind: PolicyMatchKind::Exact,
            value: "pkg:data".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };

        let result = evaluate_policy("snapshot:fixture", &graph, &config(package_rule))?;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].source.kind,
            PolicySelectorKind::Package
        );
        assert_eq!(result.violations[0].target.locator, "pkg:data");
        Ok(())
    }

    #[test]
    fn multi_hop_suppression_can_match_later_path_context() -> Result<()> {
        let mut later = edge("e2", "b", "c", "profile:production");
        later.condition = json!({
            "op":"all",
            "conditions":[
                {"op":"eq","key":"mode","value":"production"},
                {"op":"eq","key":"boundary","value":"legacy"}
            ]
        });
        let graph = snapshot(vec![edge("e1", "a", "b", "profile:production"), later]);
        let mut depth = rule(PolicyRuleKind::DependencyDepth);
        depth.source = PolicySelector {
            match_kind: PolicyMatchKind::Exact,
            value: "src/ui/a.ts".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            ..selector("unused")
        };
        depth.target = PolicySelector {
            match_kind: PolicyMatchKind::Exact,
            value: "src/data/c.ts".to_owned(),
            cardinality: PolicySelectorCardinality::One,
            ..selector("unused")
        };
        depth.threshold = Some(PolicyThreshold { max: 1 });
        let mut policy = config(depth);
        policy.suppressions.push(PolicySuppression {
            id: "legacy-path".to_owned(),
            rule_id: "fixture-rule".to_owned(),
            reason: "later hop is an approved legacy boundary".to_owned(),
            scope: PolicySuppressionScope {
                condition: Some(PolicyCondition::Eq {
                    key: "boundary".to_owned(),
                    value: json!("legacy"),
                }),
                ..PolicySuppressionScope::default()
            },
        });

        let result = evaluate_policy("snapshot:fixture", &graph, &policy)?;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.summary.suppressed, 1);
        assert_eq!(
            result.violations[0]
                .suppression
                .as_ref()
                .map(|suppression| suppression.id.as_str()),
            Some("legacy-path")
        );
        assert_eq!(result.exit_code, 0);
        Ok(())
    }

    #[test]
    fn shuffled_graph_input_produces_identical_results() -> Result<()> {
        let mut graph = snapshot(vec![
            edge("e2", "a", "c", "profile:production"),
            edge("e1", "a", "b", "profile:production"),
        ]);
        let expected = evaluate_policy(
            "snapshot:fixture",
            &graph,
            &config(rule(PolicyRuleKind::ForbiddenDependency)),
        )?;
        graph.nodes.reverse();
        graph.edges.reverse();
        graph.evidence.reverse();

        let actual = evaluate_policy(
            "snapshot:fixture",
            &graph,
            &config(rule(PolicyRuleKind::ForbiddenDependency)),
        )?;

        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn selector_exclusion_and_one_cardinality_are_enforced() {
        let mut policy_rule = rule(PolicyRuleKind::ForbiddenDependency);
        policy_rule.source.exclude.push(PolicySelectorPattern {
            field: PolicySelectorField::Path,
            match_kind: PolicyMatchKind::Glob,
            value: "src/ui/**".to_owned(),
        });
        policy_rule.source.cardinality = PolicySelectorCardinality::One;
        let graph = snapshot(vec![edge("e1", "a", "b", "profile:production")]);
        let error = evaluate_policy("snapshot:fixture", &graph, &config(policy_rule))
            .unwrap_err()
            .to_string();
        assert!(error.contains("exactly one node"));
    }

    #[test]
    fn glob_distinguishes_single_and_double_star() {
        assert!(glob_matches("src/**/index.?s", "src/ui/deep/index.ts"));
        assert!(glob_matches("src/**/index.?s", "src/index.ts"));
        assert!(!glob_matches("src/*/index.ts", "src/ui/deep/index.ts"));
        assert!(glob_matches("src/*/index.ts", "src/ui/index.ts"));
        assert!(condition_values_equal(&json!(1), &json!(1.0)));
    }
}
