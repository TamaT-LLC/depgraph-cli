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
    query::CycleLevel,
};

#[derive(Debug, thiserror::Error)]
#[error("policy evaluation exhausted its bounded work budget")]
pub(crate) struct PolicyEvaluationWorkExhausted;

#[derive(Debug, thiserror::Error)]
#[error("policy evaluation was cancelled")]
pub(crate) struct PolicyEvaluationCancelled;

#[derive(Debug, thiserror::Error)]
#[error("combined policy condition exceeds the maximum logical nesting depth")]
struct CombinedPolicyConditionDepthExceeded;

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

fn charge_sort_key_bytes_work<I>(
    len: usize,
    key_bytes: I,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()>
where
    I: IntoIterator<Item = usize>,
{
    charge_sort_work(len, work, is_cancelled)?;
    if len <= 1 {
        return Ok(());
    }
    let comparison_rounds = usize::BITS as usize - (len - 1).leading_zeros() as usize;
    for bytes in key_bytes {
        work.steps(bytes.saturating_mul(comparison_rounds), is_cancelled)?;
    }
    Ok(())
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
                for (key, value) in values {
                    work.steps(key.len().saturating_add(1), is_cancelled)?;
                    pending.push(value);
                }
            }
            Value::String(value) => work.steps(value.len(), is_cancelled)?,
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
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
            charge_ordered_collection_work(
                boundary_rule_ids.len(),
                rule.id.len(),
                work,
                is_cancelled,
            )?;
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
            boundary_violation_key_bytes(&key),
            work,
            is_cancelled,
        )?;
        work.steps(violation.id.len().saturating_add(1), is_cancelled)?;
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
            boundary_violation_key_bytes(&key),
            work,
            is_cancelled,
        )?;
        work.steps(violation.id.len().saturating_add(1), is_cancelled)?;
        after_by_key
            .entry(key)
            .or_default()
            .push(violation.id.clone());
    }
    let mut new_ids = BTreeSet::new();
    for (key, mut ids) in after_by_key {
        work.step(is_cancelled)?;
        charge_sort_key_bytes_work(ids.len(), ids.iter().map(String::len), work, is_cancelled)?;
        ids.sort();
        let mut before_id_counts = BTreeMap::<String, usize>::new();
        let mut remaining_before = 0usize;
        charge_ordered_collection_work(
            before_by_key.len(),
            boundary_violation_key_bytes(&key),
            work,
            is_cancelled,
        )?;
        for id in before_by_key.remove(&key).unwrap_or_default() {
            work.step(is_cancelled)?;
            charge_ordered_collection_work(before_id_counts.len(), id.len(), work, is_cancelled)?;
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
            charge_ordered_collection_work(new_ids.len(), id.len(), work, is_cancelled)?;
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
    let mut dependency_node_path = Vec::new();
    for step in &violation.dependency_path {
        work.step(is_cancelled)?;
        work.steps(
            step.source_id.len().saturating_add(step.target_id.len()),
            is_cancelled,
        )?;
        dependency_node_path.push((step.source_id.clone(), step.target_id.clone()));
    }
    work.steps(
        violation
            .rule_id
            .len()
            .saturating_add(violation.source.id.len())
            .saturating_add(violation.target.id.len())
            .saturating_add(violation.profile_id.as_deref().map_or(0, str::len)),
        is_cancelled,
    )?;
    Ok(BoundaryViolationComparisonKey {
        rule_id: violation.rule_id.clone(),
        source_id: violation.source.id.clone(),
        target_id: violation.target.id.clone(),
        profile_id: violation.profile_id.clone(),
        dependency_node_path,
    })
}

fn boundary_violation_key_bytes(key: &BoundaryViolationComparisonKey) -> usize {
    key.rule_id
        .len()
        .saturating_add(key.source_id.len())
        .saturating_add(key.target_id.len())
        .saturating_add(key.profile_id.as_deref().map_or(0, str::len))
        .saturating_add(
            key.dependency_node_path
                .iter()
                .map(|(source, target)| source.len().saturating_add(target.len()))
                .sum::<usize>(),
        )
}

fn violation_sort_key_bytes(violation: &PolicyViolation) -> usize {
    violation
        .rule_id
        .len()
        .saturating_add(violation.source.id.len())
        .saturating_add(violation.target.id.len())
        .saturating_add(violation.profile_id.as_deref().map_or(0, str::len))
        .saturating_add(violation.id.len())
}

fn charge_violation_stable_id_work(
    rule_id: &str,
    source_id: &str,
    target_id: &str,
    profile_id: Option<&str>,
    dependency_path: &[PolicyPathStep],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    let path_bytes = dependency_path
        .iter()
        .map(|step| {
            step.source_id
                .len()
                .saturating_add(step.edge_id.len())
                .saturating_add(step.target_id.len())
        })
        .sum::<usize>();
    // The stable-ID input is materialized as JSON and canonicalized before it
    // is hashed.  Account for object/array framing and field names per path
    // step in addition to the caller-owned string bytes.
    work.steps(
        rule_id
            .len()
            .saturating_add(source_id.len())
            .saturating_add(target_id.len())
            .saturating_add(profile_id.map_or(0, str::len))
            .saturating_add(path_bytes)
            .saturating_add(dependency_path.len().saturating_mul(128))
            .saturating_add(256),
        is_cancelled,
    )
}

fn charge_public_api_stable_id_work(
    rule_id: &str,
    before_id: Option<&str>,
    after_id: Option<&str>,
    profile_id: Option<&str>,
    changed_fields: &[String],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    work.steps(
        rule_id
            .len()
            .saturating_add(before_id.map_or(0, str::len))
            .saturating_add(after_id.map_or(0, str::len))
            .saturating_add(profile_id.map_or(0, str::len))
            .saturating_add(
                changed_fields
                    .iter()
                    .map(|field| field.len().saturating_add(32))
                    .sum::<usize>(),
            )
            .saturating_add(512),
        is_cancelled,
    )
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
    // Profile and node properties are copied into condition contexts below.
    // Validate all caller-owned JSON before that materialization so a deep
    // manually assembled value cannot recurse through `Value::clone()` even
    // when the policy has no PublicApiChange rule (the diff path performs the
    // corresponding `from`-side preflight before cloning).
    validate_snapshot_values_bounded(snapshot, "snapshot", work, is_cancelled)?;
    let mut nodes = BTreeMap::new();
    for node in &snapshot.nodes {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(nodes.len(), node.id.len(), work, is_cancelled)?;
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
            PolicyRuleKind::Cycle => evaluate_cycles_bounded(
                rule,
                &admitted,
                &source_ids,
                &target_ids,
                &nodes,
                &suppressions,
                work,
                is_cancelled,
            )?,
            PolicyRuleKind::DependencyDepth => evaluate_depth_bounded(
                rule,
                &admitted,
                &sources,
                &targets,
                &nodes,
                &suppressions,
                work,
                is_cancelled,
            )?,
            PolicyRuleKind::FanIn => evaluate_fan_in_bounded(
                rule,
                &admitted,
                &source_ids,
                &targets,
                &nodes,
                &suppressions,
                work,
                is_cancelled,
            )?,
            PolicyRuleKind::FanOut => evaluate_fan_out_bounded(
                rule,
                &admitted,
                &sources,
                &target_ids,
                &nodes,
                &suppressions,
                work,
                is_cancelled,
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
            charge_ordered_collection_work(
                violations.len(),
                violation.id.len(),
                work,
                is_cancelled,
            )?;
            violations.entry(violation.id.clone()).or_insert(violation);
        }
    }

    let mut ordered = Vec::new();
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
    charge_sort_key_bytes_work(
        ordered.len(),
        ordered.iter().map(violation_sort_key_bytes),
        work,
        is_cancelled,
    )?;
    work.step(is_cancelled)?;
    let result = PolicyResult::new(snapshot_id, ordered);
    work.step(is_cancelled)?;
    charge_sort_key_bytes_work(
        result.violations.len(),
        result.violations.iter().map(violation_sort_key_bytes),
        work,
        is_cancelled,
    )?;
    for violation in &result.violations {
        work.step(is_cancelled)?;
        work.steps(
            violation
                .dependency_path
                .len()
                .saturating_add(violation.evidence.len()),
            is_cancelled,
        )?;
    }
    result.validate()?;
    work.step(is_cancelled)?;
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
            charge_ordered_collection_work(rule_ids.len(), rule.id.len(), work, is_cancelled)?;
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

// Match serde_json's default recursion guard for general snapshot values.
// Conditions use the narrower wire-format bound below because their logical
// operator contract is stricter than arbitrary profile/node metadata.
const MAX_SNAPSHOT_JSON_DEPTH: usize = 128;

fn validate_snapshot_values_bounded(
    snapshot: &GraphSnapshot,
    description: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    for profile in &snapshot.profiles {
        work.step(is_cancelled)?;
        if let Some(value) = &profile.toolchain {
            validate_json_value_bounded(value, description, work, is_cancelled)?;
        }
        validate_json_value_bounded(&profile.environment, description, work, is_cancelled)?;
        validate_json_value_bounded(&profile.properties, description, work, is_cancelled)?;
    }
    for node in &snapshot.nodes {
        work.step(is_cancelled)?;
        validate_json_value_bounded(&node.properties, description, work, is_cancelled)?;
    }
    for site in &snapshot.sites {
        work.step(is_cancelled)?;
        validate_json_condition_value_bounded(&site.condition, description, work, is_cancelled)?;
    }
    for edge in &snapshot.edges {
        work.step(is_cancelled)?;
        validate_json_condition_value_bounded(&edge.condition, description, work, is_cancelled)?;
    }
    for evidence in &snapshot.evidence {
        work.step(is_cancelled)?;
        validate_json_value_bounded(&evidence.properties, description, work, is_cancelled)?;
    }
    for diagnostic in &snapshot.diagnostics {
        work.step(is_cancelled)?;
        validate_json_value_bounded(&diagnostic.properties, description, work, is_cancelled)?;
    }
    for entry in &snapshot.profile_matrix.entries {
        work.step(is_cancelled)?;
        validate_json_value_bounded(&entry.condition_union, description, work, is_cancelled)?;
    }
    for correlation in &snapshot.profile_matrix.correlations {
        work.step(is_cancelled)?;
        validate_json_value_bounded(
            &correlation.condition_union,
            description,
            work,
            is_cancelled,
        )?;
        for value in correlation.conditions_by_phase.values() {
            work.step(is_cancelled)?;
            validate_json_value_bounded(value, description, work, is_cancelled)?;
        }
    }
    Ok(())
}

fn validate_json_value_bounded(
    value: &Value,
    description: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    validate_json_value_bounded_at_depth(
        value,
        description,
        MAX_SNAPSHOT_JSON_DEPTH,
        work,
        is_cancelled,
    )
}

fn validate_json_condition_value_bounded(
    value: &Value,
    description: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    // Each aggregate operator contributes one JSON object and one
    // `conditions` array before its child. An `in` leaf contributes one
    // additional `values` array before its primitive value, so a logical
    // depth-16 condition can reach raw JSON depth 34.
    validate_json_value_bounded_at_depth(
        value,
        description,
        MAX_EDGE_CONDITION_JSON_DEPTH,
        work,
        is_cancelled,
    )
}

fn validate_json_value_bounded_at_depth(
    value: &Value,
    description: &str,
    maximum_depth: usize,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    let mut pending = vec![(value, 0_usize)];
    while let Some((value, depth)) = pending.pop() {
        work.step(is_cancelled)?;
        if depth > maximum_depth {
            bail!("{description} contains JSON nested deeper than {maximum_depth}");
        }
        match value {
            Value::Array(values) => {
                for value in values {
                    work.step(is_cancelled)?;
                    pending.push((value, depth.saturating_add(1)));
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    work.steps(key.len().saturating_add(1), is_cancelled)?;
                    pending.push((value, depth.saturating_add(1)));
                }
            }
            Value::String(value) => work.steps(value.len(), is_cancelled)?,
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(())
}

fn charge_snapshot_text_work(
    snapshot: &GraphSnapshot,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    fn text(
        value: &str,
        work: &mut PolicyEvaluationWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<()> {
        work.steps(value.len().saturating_add(1), is_cancelled)
    }
    fn optional_text(
        value: Option<&String>,
        work: &mut PolicyEvaluationWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<()> {
        if let Some(value) = value {
            text(value, work, is_cancelled)?;
        }
        Ok(())
    }
    fn charge_coverage(
        value: &depgraph_store::CoverageRecord,
        work: &mut PolicyEvaluationWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<()> {
        for item in value.completeness.iter().chain(&value.reasons) {
            text(item, work, is_cancelled)?;
        }
        Ok(())
    }

    text(&snapshot.scan.id, work, is_cancelled)?;
    text(&snapshot.scan.root, work, is_cancelled)?;
    text(&snapshot.scan.status, work, is_cancelled)?;
    text(&snapshot.scan.started_at, work, is_cancelled)?;
    optional_text(snapshot.scan.completed_at.as_ref(), work, is_cancelled)?;
    optional_text(snapshot.scan.error.as_ref(), work, is_cancelled)?;
    optional_text(
        snapshot.scan.parent_snapshot_id.as_ref(),
        work,
        is_cancelled,
    )?;
    optional_text(snapshot.scan.source_revision.as_ref(), work, is_cancelled)?;
    for profile in &snapshot.profiles {
        text(&profile.id, work, is_cancelled)?;
        text(&profile.language, work, is_cancelled)?;
        optional_text(profile.command.as_ref(), work, is_cancelled)?;
        optional_text(profile.target.as_ref(), work, is_cancelled)?;
        optional_text(profile.source_revision.as_ref(), work, is_cancelled)?;
        for feature in &profile.features {
            text(feature, work, is_cancelled)?;
        }
        if let Some(coverage) = &profile.coverage {
            charge_coverage(coverage, work, is_cancelled)?;
        }
    }
    for node in &snapshot.nodes {
        text(&node.id, work, is_cancelled)?;
        text(&node.kind, work, is_cancelled)?;
        text(&node.locator, work, is_cancelled)?;
        text(&node.display_name, work, is_cancelled)?;
    }
    for site in &snapshot.sites {
        text(&site.id, work, is_cancelled)?;
        text(&site.source, work, is_cancelled)?;
        text(&site.kind, work, is_cancelled)?;
        optional_text(site.specifier.as_ref(), work, is_cancelled)?;
        text(&site.profile_id, work, is_cancelled)?;
        text(&site.resolution_status, work, is_cancelled)?;
        text(&site.precision, work, is_cancelled)?;
        for target in &site.target_ids {
            text(target, work, is_cancelled)?;
        }
        optional_text(site.reason.as_ref(), work, is_cancelled)?;
    }
    for edge in &snapshot.edges {
        text(&edge.id, work, is_cancelled)?;
        optional_text(edge.site_id.as_ref(), work, is_cancelled)?;
        text(&edge.source, work, is_cancelled)?;
        text(&edge.target, work, is_cancelled)?;
        text(&edge.kind, work, is_cancelled)?;
        text(&edge.phase, work, is_cancelled)?;
        text(&edge.environment, work, is_cancelled)?;
        text(&edge.profile_id, work, is_cancelled)?;
        text(&edge.resolution_status, work, is_cancelled)?;
        text(&edge.precision, work, is_cancelled)?;
    }
    for evidence in &snapshot.evidence {
        text(&evidence.owner_type, work, is_cancelled)?;
        text(&evidence.owner_id, work, is_cancelled)?;
        text(&evidence.kind, work, is_cancelled)?;
        text(&evidence.extractor, work, is_cancelled)?;
        text(&evidence.extractor_version, work, is_cancelled)?;
        text(&evidence.path, work, is_cancelled)?;
        optional_text(evidence.detail.as_ref(), work, is_cancelled)?;
    }
    for diagnostic in &snapshot.diagnostics {
        text(&diagnostic.id, work, is_cancelled)?;
        text(&diagnostic.severity, work, is_cancelled)?;
        text(&diagnostic.code, work, is_cancelled)?;
        text(&diagnostic.message, work, is_cancelled)?;
        optional_text(diagnostic.path.as_ref(), work, is_cancelled)?;
        optional_text(diagnostic.adapter.as_ref(), work, is_cancelled)?;
    }
    for coverage in &snapshot.file_coverage {
        text(&coverage.adapter, work, is_cancelled)?;
        text(&coverage.path, work, is_cancelled)?;
        optional_text(coverage.reason.as_ref(), work, is_cancelled)?;
    }
    for log in &snapshot.adapter_logs {
        text(&log.adapter, work, is_cancelled)?;
        text(&log.stderr, work, is_cancelled)?;
    }
    charge_coverage(&snapshot.coverage, work, is_cancelled)?;
    text(&snapshot.profile_matrix.schema_version, work, is_cancelled)?;
    for entry in &snapshot.profile_matrix.entries {
        text(&entry.id, work, is_cancelled)?;
        text(&entry.effective_input_id, work, is_cancelled)?;
        text(&entry.language, work, is_cancelled)?;
        for value in entry
            .profile_ids
            .iter()
            .chain(&entry.parent_profile_ids)
            .chain(&entry.phases)
            .chain(&entry.selection_reasons)
        {
            text(value, work, is_cancelled)?;
        }
        for (key, coverage) in &entry.phase_coverage {
            text(key, work, is_cancelled)?;
            for value in coverage.profile_ids.iter().chain(&coverage.completeness) {
                text(value, work, is_cancelled)?;
            }
        }
        for conflict in &entry.axis_conflicts {
            text(&conflict.profile_id, work, is_cancelled)?;
            text(&conflict.parent_profile_id, work, is_cancelled)?;
            text(&conflict.diagnostic_id, work, is_cancelled)?;
            for field in &conflict.fields {
                text(field, work, is_cancelled)?;
            }
        }
    }
    for (key, coverage) in &snapshot.profile_matrix.phase_coverage {
        text(key, work, is_cancelled)?;
        for value in coverage.profile_ids.iter().chain(&coverage.completeness) {
            text(value, work, is_cancelled)?;
        }
    }
    for key in snapshot.profile_matrix.difference_counts.keys() {
        text(key, work, is_cancelled)?;
    }
    for correlation in &snapshot.profile_matrix.correlations {
        text(&correlation.id, work, is_cancelled)?;
        text(&correlation.effective_profile_id, work, is_cancelled)?;
        text(&correlation.source, work, is_cancelled)?;
        text(&correlation.kind, work, is_cancelled)?;
        text(&correlation.specifier, work, is_cancelled)?;
        text(&correlation.status, work, is_cancelled)?;
        optional_text(correlation.diagnostic_id.as_ref(), work, is_cancelled)?;
        for key in correlation.conditions_by_phase.keys() {
            text(key, work, is_cancelled)?;
        }
        for map in [
            &correlation.targets_by_phase,
            &correlation.resolutions_by_phase,
            &correlation.site_ids_by_phase,
            &correlation.edge_ids_by_phase,
        ] {
            for (key, values) in map {
                text(key, work, is_cancelled)?;
                for value in values {
                    text(value, work, is_cancelled)?;
                }
            }
        }
        for reason in &correlation.difference_reasons {
            text(reason, work, is_cancelled)?;
        }
    }
    Ok(())
}

fn snapshot_record_count(snapshot: &GraphSnapshot) -> usize {
    snapshot
        .profiles
        .len()
        .saturating_add(snapshot.nodes.len())
        .saturating_add(snapshot.sites.len())
        .saturating_add(snapshot.edges.len())
        .saturating_add(snapshot.evidence.len())
        .saturating_add(snapshot.diagnostics.len())
        .saturating_add(snapshot.profile_matrix.entries.len())
        .saturating_add(snapshot.profile_matrix.correlations.len())
}

fn charge_diff_precompute_work(
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    charge_snapshot_text_work(from, work, is_cancelled)?;
    charge_snapshot_text_work(to, work, is_cancelled)?;
    let records = snapshot_record_count(from)
        .saturating_add(snapshot_record_count(to))
        .saturating_add(from.file_coverage.len())
        .saturating_add(to.file_coverage.len())
        .saturating_add(from.adapter_logs.len())
        .saturating_add(to.adapter_logs.len());
    let rounds = if records == 0 {
        1
    } else {
        usize::BITS as usize - records.leading_zeros() as usize
    };
    work.steps(
        records.saturating_mul(rounds.saturating_add(8)),
        is_cancelled,
    )
}

fn changed_fields_bounded(
    fields: &[String],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<String>> {
    let mut output = Vec::new();
    for field in fields {
        work.steps(field.len().saturating_add(1), is_cancelled)?;
        output.push(field.clone());
    }
    Ok(output)
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
    let mut has_public_api_changes = false;
    for rule in &config.rules {
        work.step(is_cancelled)?;
        has_public_api_changes |= rule.kind == PolicyRuleKind::PublicApiChange;
    }
    // `evaluate_policy_with_work` can materialize profile/node values while
    // building its context.  Validate the `from` side before entering that
    // path so it is also safe when the later diff clone is reached; the `to`
    // side is preflighted at the start of `evaluate_policy_with_work`.
    if has_public_api_changes {
        validate_snapshot_values_bounded(from, "from snapshot", work, is_cancelled)?;
    }
    let current = evaluate_policy_with_work(to_snapshot_id, to, config, work, is_cancelled)?;
    if !has_public_api_changes {
        return Ok(current);
    }
    // `diff_graph_snapshots` consumes both snapshots and therefore requires a
    // clone.  Reject deep/oversized JSON and charge the clone/diff preflight
    // before that allocation so malformed snapshots cannot bypass the shared
    // policy budget through the PublicApiChange-only path.
    charge_diff_precompute_work(from, to, work, is_cancelled)?;
    work.step(is_cancelled)?;
    let diff = diff_graph_snapshots(from_snapshot_id, to_snapshot_id, from.clone(), to.clone())?;
    work.step(is_cancelled)?;
    let mut rename_pairs = Vec::new();
    for rename in &diff.renames {
        work.step(is_cancelled)?;
        rename_pairs.push((rename.old_id.as_str(), rename.new_id.as_str()));
    }
    let mut violations = BTreeMap::new();
    for violation in current.violations {
        work.step(is_cancelled)?;
        work.steps(violation.id.len().saturating_add(1), is_cancelled)?;
        charge_ordered_collection_work(violations.len(), violation.id.len(), work, is_cancelled)?;
        violations.insert(violation.id.clone(), violation);
    }
    let mut api_changes = Vec::new();
    let from_node_evidence = NodeEvidenceIndex::new_bounded(from, work, is_cancelled)?;
    let to_node_evidence = NodeEvidenceIndex::new_bounded(to, work, is_cancelled)?;

    for rule in config
        .rules
        .iter()
        .filter(|rule| rule.kind == PolicyRuleKind::PublicApiChange)
    {
        validate_diff_selector_bounded(from, to, &rule.target, &rule.id, work, is_cancelled)?;
        let suppressions = resolve_diff_suppressions_bounded(
            from,
            to,
            &rename_pairs,
            config,
            &rule.id,
            work,
            is_cancelled,
        )?;
        let admitted =
            admitted_edges_with_options_bounded(from, rule, false, false, work, is_cancelled)?;
        let mut rule_changes = Vec::new();

        for node in &diff.nodes.added {
            work.step(is_cancelled)?;
            if let Some(change) = classify_public_api_change_bounded(
                rule,
                PublicApiChangeKind::Added,
                None,
                Some(node),
                Vec::new(),
                from,
                to,
                &from_node_evidence,
                &to_node_evidence,
                work,
                is_cancelled,
            )? {
                work.step(is_cancelled)?;
                rule_changes.push((change, None));
            }
        }
        for node in &diff.nodes.removed {
            work.step(is_cancelled)?;
            if let Some(change) = classify_public_api_change_bounded(
                rule,
                PublicApiChangeKind::Removed,
                Some(node),
                None,
                Vec::new(),
                from,
                to,
                &from_node_evidence,
                &to_node_evidence,
                work,
                is_cancelled,
            )? {
                work.step(is_cancelled)?;
                rule_changes.push((change, Some(node)));
            }
        }
        for changed in &diff.nodes.changed {
            work.step(is_cancelled)?;
            if let Some(change) = classify_public_api_change_bounded(
                rule,
                PublicApiChangeKind::Changed,
                Some(&changed.before),
                Some(&changed.after),
                changed_fields_bounded(&changed.changed_fields, work, is_cancelled)?,
                from,
                to,
                &from_node_evidence,
                &to_node_evidence,
                work,
                is_cancelled,
            )? {
                work.step(is_cancelled)?;
                rule_changes.push((change, Some(&changed.before)));
            }
        }
        for rename in &diff.renames {
            work.step(is_cancelled)?;
            if let Some(change) = classify_public_api_change_bounded(
                rule,
                PublicApiChangeKind::Changed,
                Some(&rename.before),
                Some(&rename.after),
                changed_fields_bounded(&rename.changed_fields, work, is_cancelled)?,
                from,
                to,
                &from_node_evidence,
                &to_node_evidence,
                work,
                is_cancelled,
            )? {
                work.step(is_cancelled)?;
                rule_changes.push((change, Some(&rename.before)));
            }
        }

        let mut needs_impact = false;
        for (change, _) in &rule_changes {
            work.step(is_cancelled)?;
            needs_impact |= change.breaking;
        }
        let sources = needs_impact
            .then(|| {
                resolve_selector_bounded(
                    from,
                    &rule.source,
                    &format!("public API rule {:?} source", rule.id),
                    work,
                    is_cancelled,
                )
            })
            .transpose()?
            .unwrap_or_default();
        let mut nodes = BTreeMap::new();
        for node in &from.nodes {
            work.step(is_cancelled)?;
            work.steps(node.id.len().saturating_add(1), is_cancelled)?;
            charge_ordered_collection_work(nodes.len(), node.id.len(), work, is_cancelled)?;
            nodes.insert(node.id.as_str(), node);
        }

        for (change, before) in rule_changes {
            work.step(is_cancelled)?;
            if let Some(before) = before {
                for violation in evaluate_public_api_impact_bounded(
                    rule,
                    &change,
                    before,
                    &sources,
                    &admitted,
                    &nodes,
                    &suppressions,
                    from,
                    to,
                    work,
                    is_cancelled,
                )? {
                    work.step(is_cancelled)?;
                    charge_ordered_collection_work(
                        violations.len(),
                        violation.id.len(),
                        work,
                        is_cancelled,
                    )?;
                    violations.entry(violation.id.clone()).or_insert(violation);
                }
            }
            work.step(is_cancelled)?;
            api_changes.push(change);
        }
    }

    charge_sort_key_bytes_work(
        api_changes.len(),
        api_changes.iter().map(|change| {
            change
                .rule_id
                .len()
                .saturating_add(change.id.len())
                .saturating_add(change.changed_fields.iter().map(String::len).sum::<usize>())
                .saturating_add(change.before.as_ref().map_or(0, |entity| {
                    entity.id.len().saturating_add(entity.locator.len())
                }))
                .saturating_add(change.after.as_ref().map_or(0, |entity| {
                    entity.id.len().saturating_add(entity.locator.len())
                }))
                .saturating_add(change.profile_id.as_deref().map_or(0, str::len))
        }),
        work,
        is_cancelled,
    )?;
    work.steps(api_changes.len(), is_cancelled)?;
    let mut violation_values = Vec::new();
    for violation in violations.into_values() {
        work.step(is_cancelled)?;
        violation_values.push(violation);
    }
    charge_sort_key_bytes_work(
        violation_values.len(),
        violation_values.iter().map(violation_sort_key_bytes),
        work,
        is_cancelled,
    )?;
    for violation in &violation_values {
        work.step(is_cancelled)?;
        work.steps(
            violation
                .dependency_path
                .len()
                .saturating_add(violation.evidence.len()),
            is_cancelled,
        )?;
    }
    let result = PolicyResult::with_api_changes(to_snapshot_id, api_changes, violation_values);
    work.step(is_cancelled)?;
    charge_sort_key_bytes_work(
        result.api_changes.len(),
        result.api_changes.iter().map(|change| {
            change
                .rule_id
                .len()
                .saturating_add(change.id.len())
                .saturating_add(change.before.as_ref().map_or(0, |entity| entity.id.len()))
                .saturating_add(change.after.as_ref().map_or(0, |entity| entity.id.len()))
                .saturating_add(change.profile_id.as_deref().map_or(0, str::len))
        }),
        work,
        is_cancelled,
    )?;
    charge_sort_key_bytes_work(
        result.violations.len(),
        result.violations.iter().map(violation_sort_key_bytes),
        work,
        is_cancelled,
    )?;
    result.validate()?;
    work.step(is_cancelled)?;
    Ok(result)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

fn validate_diff_selector_bounded(
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    selector: &PolicySelector,
    rule_id: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    if selector.cardinality != PolicySelectorCardinality::One {
        work.step(is_cancelled)?;
        return Ok(());
    }
    let mut before = 0_usize;
    for node in &from.nodes {
        work.step(is_cancelled)?;
        if selector_matches_node_bounded(node, selector, work, is_cancelled)? {
            before = before.saturating_add(1);
        }
    }
    let mut after = 0_usize;
    for node in &to.nodes {
        work.step(is_cancelled)?;
        if selector_matches_node_bounded(node, selector, work, is_cancelled)? {
            after = after.saturating_add(1);
        }
    }
    if before > 1 || after > 1 || (before == 0 && after == 0) {
        bail!(
            "public API rule {rule_id:?} target selector must resolve to exactly one node in at least one snapshot and at most one per snapshot, but matched {before} before and {after} after"
        );
    }
    Ok(())
}

fn resolve_diff_suppressions_bounded<'a>(
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    rename_pairs: &[(&str, &str)],
    config: &'a PolicyConfig,
    rule_id: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<ResolvedSuppression<'a>>> {
    let mut resolved = Vec::new();
    for suppression in &config.suppressions {
        work.step(is_cancelled)?;
        if suppression.rule_id != rule_id {
            continue;
        }
        work.steps(
            suppression
                .id
                .len()
                .saturating_add(suppression.rule_id.len())
                .saturating_add(suppression.reason.len()),
            is_cancelled,
        )?;
        let source_ids = suppression
            .scope
            .source
            .as_ref()
            .map(|selector| {
                let description = format!("suppression {:?} source", suppression.id);
                work.steps(description.len(), is_cancelled)?;
                resolve_diff_scope_selector_bounded(
                    from,
                    to,
                    rename_pairs,
                    selector,
                    &description,
                    work,
                    is_cancelled,
                )
            })
            .transpose()?;
        let target_ids = suppression
            .scope
            .target
            .as_ref()
            .map(|selector| {
                let description = format!("suppression {:?} target", suppression.id);
                work.steps(description.len(), is_cancelled)?;
                resolve_diff_scope_selector_bounded(
                    from,
                    to,
                    rename_pairs,
                    selector,
                    &description,
                    work,
                    is_cancelled,
                )
            })
            .transpose()?;
        work.step(is_cancelled)?;
        resolved.push(ResolvedSuppression {
            suppression,
            source_ids,
            target_ids,
        });
    }
    charge_sort_key_bytes_work(
        resolved.len(),
        resolved.iter().map(|item| item.suppression.id.len()),
        work,
        is_cancelled,
    )?;
    resolved.sort_by(|left, right| left.suppression.id.cmp(&right.suppression.id));
    Ok(resolved)
}

fn resolve_diff_scope_selector_bounded(
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    rename_pairs: &[(&str, &str)],
    selector: &PolicySelector,
    description: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeSet<String>> {
    work.steps(description.len(), is_cancelled)?;
    let mut before = 0_usize;
    let mut after = 0_usize;
    let mut ids = BTreeSet::new();
    for node in &from.nodes {
        work.step(is_cancelled)?;
        if selector_matches_node_bounded(node, selector, work, is_cancelled)? {
            before = before.saturating_add(1);
            work.steps(node.id.len().saturating_add(1), is_cancelled)?;
            charge_ordered_collection_work(ids.len(), node.id.len(), work, is_cancelled)?;
            ids.insert(node.id.clone());
        }
    }
    for node in &to.nodes {
        work.step(is_cancelled)?;
        if selector_matches_node_bounded(node, selector, work, is_cancelled)? {
            after = after.saturating_add(1);
            work.steps(node.id.len().saturating_add(1), is_cancelled)?;
            charge_ordered_collection_work(ids.len(), node.id.len(), work, is_cancelled)?;
            ids.insert(node.id.clone());
        }
    }
    if selector.cardinality == PolicySelectorCardinality::One
        && (before > 1 || after > 1 || (before == 0 && after == 0))
    {
        bail!(
            "policy selector {description} must resolve to at most one node per snapshot and at least one across the diff, but matched {before} before and {after} after"
        );
    }
    for (old_id, new_id) in rename_pairs {
        work.step(is_cancelled)?;
        if ids.contains(*old_id) || ids.contains(*new_id) {
            work.steps(old_id.len().saturating_add(new_id.len()), is_cancelled)?;
            charge_ordered_collection_work(ids.len(), old_id.len(), work, is_cancelled)?;
            ids.insert((*old_id).to_owned());
            charge_ordered_collection_work(ids.len(), new_id.len(), work, is_cancelled)?;
            ids.insert((*new_id).to_owned());
        }
    }
    Ok(ids)
}

fn charge_policy_condition_work(
    condition: &PolicyCondition,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    let mut pending = vec![condition];
    while let Some(condition) = pending.pop() {
        work.step(is_cancelled)?;
        match condition {
            PolicyCondition::All { conditions } | PolicyCondition::Any { conditions } => {
                work.steps(conditions.len(), is_cancelled)?;
                pending.extend(conditions.iter());
            }
            PolicyCondition::Not { condition } => pending.push(condition),
            PolicyCondition::Eq { key, value } => {
                work.steps(key.len().saturating_add(1), is_cancelled)?;
                charge_json_value_work(value, work, is_cancelled)?;
            }
            PolicyCondition::In { key, values } => {
                work.steps(key.len().saturating_add(1), is_cancelled)?;
                work.steps(values.len(), is_cancelled)?;
                for value in values {
                    charge_json_value_work(value, work, is_cancelled)?;
                }
            }
            PolicyCondition::Defined { key } => {
                work.steps(key.len().saturating_add(1), is_cancelled)?;
            }
        }
    }
    Ok(())
}

fn policy_entity_bounded(
    node: &NodeRecord,
    kind: PolicySelectorKind,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyEntity> {
    work.steps(
        node.id
            .len()
            .saturating_add(node.locator.len())
            .saturating_add(1),
        is_cancelled,
    )?;
    Ok(PolicyEntity {
        id: node.id.clone(),
        kind,
        locator: node.locator.clone(),
    })
}

fn merge_object_bounded(
    context: &mut BTreeMap<String, Value>,
    value: &Value,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            work.steps(key.len().saturating_add(1), is_cancelled)?;
            charge_json_value_work(value, work, is_cancelled)?;
            charge_ordered_collection_work(context.len(), key.len(), work, is_cancelled)?;
            context.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    Ok(())
}

fn public_api_change_context_bounded(
    before: Option<&NodeRecord>,
    after: Option<&NodeRecord>,
    profile: Option<&ProfileRecord>,
    kind: PublicApiChangeKind,
    changed_fields: &[String],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<String, Value>> {
    let mut context = BTreeMap::new();
    if let Some(profile) = profile {
        merge_object_bounded(&mut context, &profile.environment, work, is_cancelled)?;
        merge_object_bounded(&mut context, &profile.properties, work, is_cancelled)?;
        work.steps(profile.language.len().saturating_add(1), is_cancelled)?;
        context.insert(
            "language".to_owned(),
            Value::String(profile.language.clone()),
        );
        if let Some(target) = &profile.target {
            work.steps(target.len().saturating_add(1), is_cancelled)?;
            context.insert("target".to_owned(), Value::String(target.clone()));
        }
        if let Some(command) = &profile.command {
            work.steps(command.len().saturating_add(1), is_cancelled)?;
            context.insert("command".to_owned(), Value::String(command.clone()));
        }
        let mut features = Vec::new();
        for feature in &profile.features {
            work.steps(feature.len().saturating_add(1), is_cancelled)?;
            features.push(Value::String(feature.clone()));
        }
        context.insert("features".to_owned(), Value::Array(features));
        work.steps(profile.id.len().saturating_add(1), is_cancelled)?;
        context.insert("profile".to_owned(), Value::String(profile.id.clone()));
        work.steps(profile.id.len().saturating_add(1), is_cancelled)?;
        context.insert("profile_id".to_owned(), Value::String(profile.id.clone()));
    }
    if let Some(node) = after.or(before) {
        merge_object_bounded(&mut context, &node.properties, work, is_cancelled)?;
    }
    let mut change = serde_json::Map::new();
    work.steps(1, is_cancelled)?;
    change.insert(
        "kind".to_owned(),
        Value::String(public_api_change_kind_name(kind).to_owned()),
    );
    work.steps(1, is_cancelled)?;
    change.insert(
        "breaking".to_owned(),
        Value::Bool(kind != PublicApiChangeKind::Added),
    );
    let mut fields = Vec::new();
    for field in changed_fields {
        work.steps(field.len().saturating_add(1), is_cancelled)?;
        fields.push(Value::String(field.clone()));
    }
    change.insert("changed_fields".to_owned(), Value::Array(fields));
    work.steps(1, is_cancelled)?;
    context.insert("change".to_owned(), Value::Object(change));
    Ok(context)
}

fn node_policy_evidence_bounded(
    index: &NodeEvidenceIndex<'_>,
    node: &NodeRecord,
    requirement: &PolicyEvidenceRequirement,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PolicyEvidenceSpan>> {
    let records = index
        .records
        .get(node.id.as_str())
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut spans = Vec::new();
    for record in records {
        work.step(is_cancelled)?;
        if requirement.primary_only && record.ordinal != 0 {
            continue;
        }
        work.steps(
            record.kind.len().saturating_add(record.path.len()),
            is_cancelled,
        )?;
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
        work.steps(path.len().saturating_add(1), is_cancelled)?;
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
    canonicalize_evidence_bounded(&mut spans, work, is_cancelled)?;
    Ok(spans)
}

fn append_unique_evidence_bounded(
    destination: &mut Vec<PolicyEvidenceSpan>,
    evidence: Vec<PolicyEvidenceSpan>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    for span in evidence {
        work.step(is_cancelled)?;
        let mut duplicate = false;
        for existing in destination.iter() {
            work.step(is_cancelled)?;
            work.steps(
                existing.path.len().saturating_add(span.path.len()),
                is_cancelled,
            )?;
            if existing == &span {
                duplicate = true;
                break;
            }
        }
        if !duplicate {
            work.step(is_cancelled)?;
            destination.push(span);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn classify_public_api_change_bounded(
    rule: &PolicyRule,
    kind: PublicApiChangeKind,
    before: Option<&NodeRecord>,
    after: Option<&NodeRecord>,
    mut changed_fields: Vec<String>,
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    from_node_evidence: &NodeEvidenceIndex<'_>,
    to_node_evidence: &NodeEvidenceIndex<'_>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<PublicApiChange>> {
    work.step(is_cancelled)?;
    let before_matches = before
        .map(|node| selector_matches_node_bounded(node, &rule.target, work, is_cancelled))
        .transpose()?
        .unwrap_or(false);
    let after_matches = after
        .map(|node| selector_matches_node_bounded(node, &rule.target, work, is_cancelled))
        .transpose()?
        .unwrap_or(false);
    if !before_matches && !after_matches {
        return Ok(None);
    }
    charge_sort_work(changed_fields.len(), work, is_cancelled)?;
    for field in &changed_fields {
        work.steps(field.len().saturating_add(1), is_cancelled)?;
    }
    changed_fields.sort();
    changed_fields.dedup();
    let node = after.or(before).context("public API change has no node")?;
    let profile_id = if let Some(profile_id) = node_profile_id(node) {
        work.steps(profile_id.len().saturating_add(1), is_cancelled)?;
        Some(profile_id.to_owned())
    } else {
        None
    };
    let profile_matches = match profile_id.as_deref() {
        Some(profile_id) => {
            profile_matches_bounded(&rule.profiles, profile_id, work, is_cancelled)?
        }
        None => rule.profiles == PolicyProfileFilter::default(),
    };
    if !profile_matches {
        return Ok(None);
    }
    let profiles = if after.is_some() {
        &to.profiles
    } else {
        &from.profiles
    };
    let profile = if let Some(profile_id) = profile_id.as_deref() {
        let mut found = None;
        for candidate in profiles {
            work.step(is_cancelled)?;
            if candidate.id == profile_id {
                found = Some(candidate);
                break;
            }
        }
        found
    } else {
        None
    };
    let context = public_api_change_context_bounded(
        before,
        after,
        profile,
        kind,
        &changed_fields,
        work,
        is_cancelled,
    )?;
    if evaluate_condition_bounded_inner(&rule.condition, &context, false, work, is_cancelled)?
        != Some(true)
    {
        return Ok(None);
    }

    let mut evidence = Vec::new();
    if let Some(after) = after {
        append_unique_evidence_bounded(
            &mut evidence,
            node_policy_evidence_bounded(
                to_node_evidence,
                after,
                &rule.evidence,
                work,
                is_cancelled,
            )?,
            work,
            is_cancelled,
        )?;
    }
    if let Some(before) = before {
        append_unique_evidence_bounded(
            &mut evidence,
            node_policy_evidence_bounded(
                from_node_evidence,
                before,
                &rule.evidence,
                work,
                is_cancelled,
            )?,
            work,
            is_cancelled,
        )?;
    }
    if evidence.len() < usize::try_from(rule.evidence.minimum_spans)? {
        return Ok(None);
    }

    charge_policy_condition_work(&rule.condition, work, is_cancelled)?;
    work.steps(3, is_cancelled)?;
    let condition = canonical_condition_bounded(
        &PolicyCondition::All {
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
        },
        work,
        is_cancelled,
    )?;
    let before_entity = before
        .map(|node| policy_entity_bounded(node, rule.target.kind, work, is_cancelled))
        .transpose()?;
    let after_entity = after
        .map(|node| policy_entity_bounded(node, rule.target.kind, work, is_cancelled))
        .transpose()?;
    charge_public_api_stable_id_work(
        &rule.id,
        before_entity.as_ref().map(|entity| entity.id.as_str()),
        after_entity.as_ref().map(|entity| entity.id.as_str()),
        profile_id.as_deref(),
        &changed_fields,
        work,
        is_cancelled,
    )?;
    let id = PublicApiChange::stable_id(
        &rule.id,
        kind,
        before_entity.as_ref().map(|entity| entity.id.as_str()),
        after_entity.as_ref().map(|entity| entity.id.as_str()),
        profile_id.as_deref(),
        &changed_fields,
    );
    work.steps(rule.id.len().saturating_add(1), is_cancelled)?;
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
fn evaluate_public_api_impact_bounded(
    rule: &PolicyRule,
    change: &PublicApiChange,
    before: &NodeRecord,
    sources: &[&NodeRecord],
    admitted: &[AdmittedEdge<'_>],
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PolicyViolation>> {
    let baseline_profile_id = node_profile_id(before);
    let mut by_profile: BTreeMap<&str, Vec<&AdmittedEdge<'_>>> = BTreeMap::new();
    for item in admitted {
        work.step(is_cancelled)?;
        if baseline_profile_id.is_some_and(|profile_id| item.edge.profile_id != profile_id) {
            continue;
        }
        charge_ordered_collection_work(
            by_profile.len(),
            item.edge.profile_id.len(),
            work,
            is_cancelled,
        )?;
        by_profile
            .entry(item.edge.profile_id.as_str())
            .or_default()
            .push(item);
    }
    let mut output = BTreeMap::new();
    for (profile_id, edges) in by_profile {
        work.step(is_cancelled)?;
        let adjacency = adjacency_bounded(&edges, work, is_cancelled)?;
        for source in sources {
            work.step(is_cancelled)?;
            work.steps(
                source.id.len().saturating_mul(2).saturating_add(1),
                is_cancelled,
            )?;
            let mut visited = BTreeSet::new();
            let source_id = source.id.clone();
            visited.insert(source_id.clone());
            let mut predecessor: HashMap<String, &AdmittedEdge<'_>> = HashMap::new();
            let mut queue = VecDeque::new();
            queue.push_back(source_id);
            while let Some(current) = queue.pop_front() {
                work.step(is_cancelled)?;
                if let Some(outgoing) = adjacency.get(current.as_str()) {
                    for item in outgoing {
                        work.step(is_cancelled)?;
                        let target_id = item.edge.target.as_str();
                        work.steps(target_id.len().saturating_add(1), is_cancelled)?;
                        charge_ordered_collection_work(
                            visited.len(),
                            target_id.len(),
                            work,
                            is_cancelled,
                        )?;
                        if !visited.contains(target_id) {
                            // The target is owned by each of the visited,
                            // predecessor, and queue collections. Charge all
                            // three copies before allocating any of them.
                            work.steps(target_id.len().saturating_mul(3), is_cancelled)?;
                            charge_ordered_collection_work(
                                predecessor.len(),
                                target_id.len(),
                                work,
                                is_cancelled,
                            )?;
                            let target_id = target_id.to_owned();
                            visited.insert(target_id.clone());
                            predecessor.insert(target_id.clone(), item);
                            queue.push_back(target_id);
                        }
                    }
                }
            }
            if !visited.contains(&before.id) {
                continue;
            }
            let path_edges =
                reconstruct_path_bounded(&source.id, &before.id, &predecessor, work, is_cancelled)?;
            if path_edges.is_empty() {
                continue;
            }
            let violation = make_public_api_violation_bounded(
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
                work,
                is_cancelled,
            )?;
            work.step(is_cancelled)?;
            work.steps(violation.id.len().saturating_add(1), is_cancelled)?;
            charge_ordered_collection_work(output.len(), violation.id.len(), work, is_cancelled)?;
            output.entry(violation.id.clone()).or_insert(violation);
        }
    }
    for source in sources {
        work.step(is_cancelled)?;
        if source.id != before.id {
            continue;
        }
        let violation = make_public_api_violation_bounded(
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
            work,
            is_cancelled,
        )?;
        work.step(is_cancelled)?;
        work.steps(violation.id.len().saturating_add(1), is_cancelled)?;
        charge_ordered_collection_work(output.len(), violation.id.len(), work, is_cancelled)?;
        output.entry(violation.id.clone()).or_insert(violation);
    }
    let mut values = Vec::new();
    for violation in output.into_values() {
        work.step(is_cancelled)?;
        values.push(violation);
    }
    Ok(values)
}

#[allow(clippy::too_many_arguments)]
fn make_public_api_violation_bounded(
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
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyViolation> {
    work.step(is_cancelled)?;
    work.steps(
        source
            .id
            .len()
            .saturating_add(target.id.len())
            .saturating_add(1),
        is_cancelled,
    )?;
    if !nodes.contains_key(source.id.as_str()) || !nodes.contains_key(target.id.as_str()) {
        bail!("public API impact path references a node missing from the baseline snapshot");
    }
    let mut dependency_path = Vec::new();
    if path_edges.is_empty() {
        work.steps(
            source
                .id
                .len()
                .saturating_add(target.id.len())
                .saturating_add(change.id.len()),
            is_cancelled,
        )?;
        dependency_path.push(PolicyPathStep {
            source_id: source.id.clone(),
            edge_id: change.id.clone(),
            target_id: target.id.clone(),
        });
    } else {
        for item in &path_edges {
            work.step(is_cancelled)?;
            work.steps(
                item.edge
                    .source
                    .len()
                    .saturating_add(item.edge.id.len())
                    .saturating_add(item.edge.target.len()),
                is_cancelled,
            )?;
            dependency_path.push(path_step_bounded(item.edge, work, is_cancelled)?);
        }
    }

    let mut evidence = Vec::new();
    for span in &change.evidence {
        work.step(is_cancelled)?;
        work.steps(span.path.len().saturating_add(1), is_cancelled)?;
        append_unique_evidence_bounded(&mut evidence, vec![span.clone()], work, is_cancelled)?;
    }
    for item in &path_edges {
        work.step(is_cancelled)?;
        let mut spans = Vec::new();
        for span in &item.evidence {
            work.step(is_cancelled)?;
            work.steps(span.path.len().saturating_add(1), is_cancelled)?;
            spans.push(span.clone());
        }
        append_unique_evidence_bounded(&mut evidence, spans, work, is_cancelled)?;
    }
    canonicalize_evidence_bounded(&mut evidence, work, is_cancelled)?;

    charge_policy_condition_work(&change.condition, work, is_cancelled)?;
    let mut conditions = vec![change.condition.clone()];
    if !path_edges.is_empty() {
        conditions.push(combined_condition_bounded(&path_edges, work, is_cancelled)?);
    }
    let condition =
        canonical_condition_bounded(&PolicyCondition::All { conditions }, work, is_cancelled)?;

    let mut context = combined_context_bounded(&path_edges, work, is_cancelled)?;
    let profiles = if change.after.is_some() {
        &to.profiles
    } else {
        &from.profiles
    };
    let node_profile = if let Some(profile_id) = change.profile_id.as_deref() {
        let mut found = None;
        for profile in profiles {
            work.step(is_cancelled)?;
            if profile.id == profile_id {
                found = Some(profile);
                break;
            }
        }
        found
    } else {
        None
    };
    let after_node = if let Some(after) = change.after.as_ref() {
        let mut found = None;
        for node in &to.nodes {
            work.step(is_cancelled)?;
            work.steps(after.id.len().saturating_add(node.id.len()), is_cancelled)?;
            if node.id == after.id {
                found = Some(node);
                break;
            }
        }
        found
    } else {
        None
    };
    for (key, value) in public_api_change_context_bounded(
        Some(target),
        after_node,
        node_profile,
        change.kind,
        &change.changed_fields,
        work,
        is_cancelled,
    )? {
        work.step(is_cancelled)?;
        work.steps(key.len().saturating_add(1), is_cancelled)?;
        charge_ordered_collection_work(context.len(), key.len(), work, is_cancelled)?;
        context.entry(key).or_insert(value);
    }
    let suppression = applied_suppression_bounded(
        suppressions,
        &rule.id,
        &source.id,
        &target.id,
        profile_id,
        &context,
        work,
        is_cancelled,
    )?;
    charge_violation_stable_id_work(
        &rule.id,
        &source.id,
        &target.id,
        profile_id,
        &dependency_path,
        work,
        is_cancelled,
    )?;
    let id = PolicyViolation::stable_id(
        &rule.id,
        &source.id,
        &target.id,
        profile_id,
        &dependency_path,
    );
    let message_len = "breaking public API "
        .len()
        .saturating_add(public_api_change_kind_name(change.kind).len())
        .saturating_add(" for ".len())
        .saturating_add(target.id.len())
        .saturating_add(" impacts ".len())
        .saturating_add(source.id.len());
    work.steps(message_len.saturating_add(1), is_cancelled)?;
    let message = format!(
        "breaking public API {} for {} impacts {}",
        public_api_change_kind_name(change.kind),
        target.id,
        source.id
    );
    let source_entity = policy_entity_bounded(source, rule.source.kind, work, is_cancelled)?;
    let target_entity = policy_entity_bounded(target, rule.target.kind, work, is_cancelled)?;
    let change_id = {
        work.steps(change.id.len().saturating_add(1), is_cancelled)?;
        Some(change.id.clone())
    };
    let owned_profile_id = profile_id.map(|profile_id| {
        // The bytes were charged above with the stable-ID input.
        profile_id.to_owned()
    });
    work.steps(rule.id.len().saturating_add(1), is_cancelled)?;
    Ok(PolicyViolation {
        id,
        rule_id: rule.id.clone(),
        severity: rule.severity,
        message,
        source: source_entity,
        target: target_entity,
        dependency_path,
        profile_id: owned_profile_id,
        condition,
        evidence,
        change_id,
        suppression,
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    #[allow(dead_code)]
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

    fn new_bounded(
        snapshot: &'a GraphSnapshot,
        work: &mut PolicyEvaluationWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self> {
        let mut evidence_by_owner: BTreeMap<(&str, &str), Vec<&EvidenceRecord>> = BTreeMap::new();
        let mut records: BTreeMap<&str, Vec<&EvidenceRecord>> = BTreeMap::new();
        for evidence in &snapshot.evidence {
            work.step(is_cancelled)?;
            work.steps(
                evidence
                    .owner_type
                    .len()
                    .saturating_add(evidence.owner_id.len())
                    .saturating_add(evidence.kind.len())
                    .saturating_add(evidence.path.len()),
                is_cancelled,
            )?;
            charge_ordered_collection_work(
                evidence_by_owner.len(),
                evidence
                    .owner_type
                    .len()
                    .saturating_add(evidence.owner_id.len()),
                work,
                is_cancelled,
            )?;
            evidence_by_owner
                .entry((evidence.owner_type.as_str(), evidence.owner_id.as_str()))
                .or_default()
                .push(evidence);
            if evidence.owner_type == "node" {
                charge_ordered_collection_work(
                    records.len(),
                    evidence.owner_id.len(),
                    work,
                    is_cancelled,
                )?;
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
            work.step(is_cancelled)?;
            work.steps(
                edge.id
                    .len()
                    .saturating_add(edge.site_id.as_deref().map_or(0, str::len)),
                is_cancelled,
            )?;
            let mut related =
                if let Some(found) = evidence_by_owner.get(&("edge", edge.id.as_str())) {
                    work.steps(found.len(), is_cancelled)?;
                    found.clone()
                } else {
                    Vec::new()
                };
            if related.is_empty()
                && let Some(site_id) = edge.site_id.as_deref()
                && let Some(found) = evidence_by_owner.get(&("site", site_id))
            {
                work.steps(found.len(), is_cancelled)?;
                related = found.clone();
            }
            charge_ordered_collection_work(records.len(), edge.target.len(), work, is_cancelled)?;
            work.steps(related.len(), is_cancelled)?;
            records
                .entry(edge.target.as_str())
                .or_default()
                .extend(related);
        }
        for records in records.values_mut() {
            charge_sort_key_bytes_work(
                records.len(),
                records.iter().map(|record| {
                    record
                        .kind
                        .len()
                        .saturating_add(record.path.len())
                        .saturating_add(record.owner_type.len())
                        .saturating_add(record.owner_id.len())
                }),
                work,
                is_cancelled,
            )?;
            for record in records.iter() {
                work.steps(
                    record
                        .kind
                        .len()
                        .saturating_add(record.path.len())
                        .saturating_add(record.owner_type.len())
                        .saturating_add(record.owner_id.len()),
                    is_cancelled,
                )?;
            }
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
        Ok(Self { records })
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
    let mut resolved = Vec::new();
    for suppression in &config.suppressions {
        work.step(is_cancelled)?;
        if rule_id.is_some_and(|rule_id| suppression.rule_id != rule_id) {
            continue;
        }
        work.steps(
            suppression
                .id
                .len()
                .saturating_add(suppression.rule_id.len())
                .saturating_add(suppression.reason.len()),
            is_cancelled,
        )?;
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
    charge_sort_key_bytes_work(
        resolved.len(),
        resolved.iter().map(|item| item.suppression.id.len()),
        work,
        is_cancelled,
    )?;
    resolved.sort_by(|left, right| left.suppression.id.cmp(&right.suppression.id));
    Ok(resolved)
}

#[allow(dead_code)]
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
        charge_ordered_collection_work(profiles.len(), profile.id.len(), work, is_cancelled)?;
        profiles.insert(profile.id.as_str(), profile);
    }
    let evidence: BTreeMap<_, Vec<_>> = {
        let mut by_owner: BTreeMap<(&str, &str), Vec<&EvidenceRecord>> = BTreeMap::new();
        for item in &snapshot.evidence {
            work.step(is_cancelled)?;
            charge_ordered_collection_work(
                by_owner.len(),
                item.owner_type.len().saturating_add(item.owner_id.len()),
                work,
                is_cancelled,
            )?;
            by_owner
                .entry((item.owner_type.as_str(), item.owner_id.as_str()))
                .or_default()
                .push(item);
        }
        by_owner
    };
    let allowed_precisions = serialized_names_bounded(&rule.precisions, work, is_cancelled)?;
    let allowed_statuses = serialized_names_bounded(&rule.resolution_statuses, work, is_cancelled)?;
    let mut admitted = Vec::new();

    for edge in &snapshot.edges {
        work.step(is_cancelled)?;
        if !profile_matches_bounded(&rule.profiles, &edge.profile_id, work, is_cancelled)?
            || !allowed_precisions.contains(edge.precision.as_str())
            || !allowed_statuses.contains(edge.resolution_status.as_str())
        {
            continue;
        }

        let condition = parse_condition_bounded(&edge.condition, &edge.id, work, is_cancelled)?;
        let mut context = edge_context_bounded(
            edge,
            profiles.get(edge.profile_id.as_str()).copied(),
            work,
            is_cancelled,
        )?;
        if evaluate_edge_condition_bounded(&condition, &context, work, is_cancelled)? == Some(false)
        {
            continue;
        }
        add_condition_facts_bounded(&condition, &mut context, work, is_cancelled)?;
        if apply_rule_condition
            && evaluate_condition_bounded_inner(
                &rule.condition,
                &context,
                false,
                work,
                is_cancelled,
            )? != Some(true)
        {
            continue;
        }

        let spans = select_evidence_bounded(edge, &rule.evidence, &evidence, work, is_cancelled)?;
        if require_evidence && spans.len() < usize::try_from(rule.evidence.minimum_spans)? {
            continue;
        }
        work.step(is_cancelled)?;
        admitted.push(AdmittedEdge {
            edge,
            condition: canonical_condition_bounded(&condition, work, is_cancelled)?,
            evidence: spans,
            context,
        });
    }
    charge_sort_key_bytes_work(
        admitted.len(),
        admitted.iter().map(|item| {
            item.edge
                .profile_id
                .len()
                .saturating_add(item.edge.source.len())
                .saturating_add(item.edge.target.len())
                .saturating_add(item.edge.id.len())
        }),
        work,
        is_cancelled,
    )?;
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
        charge_ordered_collection_work(
            by_profile.len(),
            item.edge.profile_id.len(),
            work,
            is_cancelled,
        )?;
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
                && evaluate_condition_bounded_inner(
                    &rule.condition,
                    &item.context,
                    false,
                    work,
                    is_cancelled,
                )? == Some(true)
            {
                boundaries.push(*item);
            }
        }

        for source in sources {
            work.step(is_cancelled)?;
            work.steps(
                source.id.len().saturating_mul(2).saturating_add(1),
                is_cancelled,
            )?;
            let source_id = source.id.clone();
            let mut visited = BTreeSet::from([source_id.clone()]);
            let mut predecessor: HashMap<String, &AdmittedEdge<'_>> = HashMap::new();
            let mut queue = VecDeque::from([source_id]);
            while let Some(current) = queue.pop_front() {
                work.step(is_cancelled)?;
                for item in adjacency.get(current.as_str()).into_iter().flatten() {
                    work.step(is_cancelled)?;
                    let target_id = item.edge.target.as_str();
                    work.steps(target_id.len().saturating_add(1), is_cancelled)?;
                    charge_ordered_collection_work(
                        visited.len(),
                        target_id.len(),
                        work,
                        is_cancelled,
                    )?;
                    if !visited.contains(target_id) {
                        work.steps(target_id.len().saturating_mul(3), is_cancelled)?;
                        charge_ordered_collection_work(
                            predecessor.len(),
                            target_id.len(),
                            work,
                            is_cancelled,
                        )?;
                        let target_id = target_id.to_owned();
                        visited.insert(target_id.clone());
                        predecessor.insert(target_id.clone(), item);
                        queue.push_back(target_id);
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
                let mut path = Vec::new();
                for item in &path_edges {
                    work.step(is_cancelled)?;
                    path.push(path_step_bounded(item.edge, work, is_cancelled)?);
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
                work.steps(violation.id.len().saturating_add(1), is_cancelled)?;
                charge_ordered_collection_work(
                    output.len(),
                    violation.id.len(),
                    work,
                    is_cancelled,
                )?;
                output.entry(violation.id.clone()).or_insert(violation);
            }
        }
    }
    let mut violations = Vec::new();
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
        let path = vec![path_step_bounded(item.edge, work, is_cancelled)?];
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

fn cycle_rings_bounded(
    nodes: &BTreeMap<&str, &NodeRecord>,
    edges: &[&AdmittedEdge<'_>],
    level: CycleLevel,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<Vec<String>>> {
    let mut allowed = BTreeSet::new();
    for item in edges {
        for node_id in [item.edge.source.as_str(), item.edge.target.as_str()] {
            work.step(is_cancelled)?;
            if nodes
                .get(node_id)
                .is_some_and(|node| node.kind == level.node_kind())
            {
                charge_ordered_collection_work(allowed.len(), node_id.len(), work, is_cancelled)?;
                allowed.insert(node_id);
            }
        }
    }

    let mut adjacency = BTreeMap::<&str, Vec<&str>>::new();
    let mut reverse = BTreeMap::<&str, Vec<&str>>::new();
    for node_id in &allowed {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(adjacency.len(), node_id.len(), work, is_cancelled)?;
        adjacency.insert(*node_id, Vec::new());
        charge_ordered_collection_work(reverse.len(), node_id.len(), work, is_cancelled)?;
        reverse.insert(*node_id, Vec::new());
    }
    for item in edges {
        work.step(is_cancelled)?;
        let source = item.edge.source.as_str();
        let target = item.edge.target.as_str();
        if allowed.contains(source) && allowed.contains(target) {
            adjacency
                .get_mut(source)
                .context("cycle adjacency lost an allowed source")?
                .push(target);
            reverse
                .get_mut(target)
                .context("cycle adjacency lost an allowed target")?
                .push(source);
        }
    }
    for targets in adjacency.values_mut().chain(reverse.values_mut()) {
        charge_sort_key_bytes_work(
            targets.len(),
            targets.iter().map(|target| target.len()),
            work,
            is_cancelled,
        )?;
        work.steps(targets.len(), is_cancelled)?;
        targets.sort_unstable();
        targets.dedup();
    }

    // Iterative Kosaraju keeps both SCC passes stack-safe and gives every
    // visited node/edge an explicit cancellation and work-budget point.
    let mut visited = BTreeSet::new();
    let mut finish_order = Vec::new();
    for node_id in &allowed {
        work.step(is_cancelled)?;
        if visited.contains(node_id) {
            continue;
        }
        charge_ordered_collection_work(visited.len(), node_id.len(), work, is_cancelled)?;
        visited.insert(*node_id);
        let mut stack = vec![(*node_id, 0_usize)];
        while let Some((current, next_index)) = stack.last().copied() {
            work.step(is_cancelled)?;
            let outgoing = adjacency
                .get(current)
                .context("cycle adjacency lost a visited node")?;
            if next_index < outgoing.len() {
                stack.last_mut().expect("stack is non-empty").1 += 1;
                let next = outgoing[next_index];
                if !visited.contains(next) {
                    charge_ordered_collection_work(visited.len(), next.len(), work, is_cancelled)?;
                    visited.insert(next);
                    stack.push((next, 0));
                }
            } else {
                stack.pop();
                finish_order.push(current);
            }
        }
    }

    let mut assigned = BTreeSet::new();
    let mut components = Vec::new();
    for node_id in finish_order.iter().rev().copied() {
        work.step(is_cancelled)?;
        if assigned.contains(node_id) {
            continue;
        }
        charge_ordered_collection_work(assigned.len(), node_id.len(), work, is_cancelled)?;
        assigned.insert(node_id);
        let mut stack = vec![node_id];
        let mut component = Vec::new();
        while let Some(current) = stack.pop() {
            work.step(is_cancelled)?;
            component.push(current);
            for next in reverse
                .get(current)
                .context("reverse cycle adjacency lost a visited node")?
            {
                work.step(is_cancelled)?;
                if !assigned.contains(next) {
                    charge_ordered_collection_work(assigned.len(), next.len(), work, is_cancelled)?;
                    assigned.insert(*next);
                    stack.push(*next);
                }
            }
        }
        charge_sort_key_bytes_work(
            component.len(),
            component.iter().map(|node| node.len()),
            work,
            is_cancelled,
        )?;
        component.sort_unstable();
        components.push(component);
    }

    let mut rings = Vec::new();
    for component in components {
        work.step(is_cancelled)?;
        let self_loop = if component.len() == 1 {
            let mut found = false;
            for target in adjacency
                .get(component[0])
                .context("cycle component lost its adjacency")?
            {
                work.step(is_cancelled)?;
                if *target == component[0] {
                    found = true;
                    break;
                }
            }
            found
        } else {
            false
        };
        if component.len() < 2 && !self_loop {
            continue;
        }
        let mut component_set = BTreeSet::new();
        for node_id in &component {
            work.step(is_cancelled)?;
            charge_ordered_collection_work(component_set.len(), node_id.len(), work, is_cancelled)?;
            component_set.insert(*node_id);
        }
        let ring = if let Some(ring) = representative_cycle_bounded(
            component[0],
            &component_set,
            &adjacency,
            work,
            is_cancelled,
        )? {
            ring
        } else {
            let mut fallback = Vec::new();
            for node_id in &component {
                work.step(is_cancelled)?;
                work.steps(node_id.len().saturating_add(1), is_cancelled)?;
                fallback.push((*node_id).to_owned());
            }
            work.step(is_cancelled)?;
            work.steps(component[0].len().saturating_add(1), is_cancelled)?;
            fallback.push(component[0].to_owned());
            fallback
        };
        rings.push(ring);
    }
    charge_sort_key_bytes_work(
        rings.len(),
        rings
            .iter()
            .map(|ring| ring.iter().map(String::len).sum::<usize>()),
        work,
        is_cancelled,
    )?;
    rings.sort();
    Ok(rings)
}

fn representative_cycle_bounded(
    start: &str,
    component: &BTreeSet<&str>,
    adjacency: &BTreeMap<&str, Vec<&str>>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<Vec<String>>> {
    let mut queue = VecDeque::new();
    let mut predecessor = BTreeMap::<&str, &str>::new();
    for next in adjacency
        .get(start)
        .context("cycle representative start has no adjacency")?
    {
        work.step(is_cancelled)?;
        if !component.contains(next) {
            continue;
        }
        if *next == start {
            work.steps(
                start.len().saturating_mul(2).saturating_add(2),
                is_cancelled,
            )?;
            return Ok(Some(vec![start.to_owned(), start.to_owned()]));
        }
        charge_ordered_collection_work(predecessor.len(), next.len(), work, is_cancelled)?;
        predecessor.insert(*next, start);
        queue.push_back(*next);
    }
    while let Some(node) = queue.pop_front() {
        work.step(is_cancelled)?;
        for next in adjacency
            .get(node)
            .context("cycle representative node has no adjacency")?
        {
            work.step(is_cancelled)?;
            if !component.contains(next) {
                continue;
            }
            if *next == start {
                work.steps(node.len().saturating_add(1), is_cancelled)?;
                let mut path = vec![node.to_owned()];
                let mut current = node;
                while current != start {
                    work.step(is_cancelled)?;
                    current = predecessor
                        .get(current)
                        .copied()
                        .context("cycle representative predecessor is missing")?;
                    work.steps(current.len().saturating_add(1), is_cancelled)?;
                    path.push(current.to_owned());
                }
                path.reverse();
                work.steps(start.len().saturating_add(1), is_cancelled)?;
                path.push(start.to_owned());
                return Ok(Some(path));
            }
            if !predecessor.contains_key(next) {
                charge_ordered_collection_work(predecessor.len(), next.len(), work, is_cancelled)?;
                predecessor.insert(*next, node);
                queue.push_back(*next);
            }
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_cycles_bounded(
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    source_ids: &BTreeSet<&str>,
    target_ids: &BTreeSet<&str>,
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PolicyViolation>> {
    let level = cycle_level(rule.source.kind)
        .with_context(|| format!("cycle rule {:?} uses an unsupported selector kind", rule.id))?;
    let mut cycle_nodes = BTreeSet::new();
    for node_id in source_ids.iter().chain(target_ids) {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(cycle_nodes.len(), node_id.len(), work, is_cancelled)?;
        cycle_nodes.insert(*node_id);
    }
    let mut by_profile: BTreeMap<&str, Vec<&AdmittedEdge<'_>>> = BTreeMap::new();
    for item in admitted {
        work.step(is_cancelled)?;
        if cycle_nodes.contains(item.edge.source.as_str())
            && cycle_nodes.contains(item.edge.target.as_str())
        {
            charge_ordered_collection_work(
                by_profile.len(),
                item.edge.profile_id.len(),
                work,
                is_cancelled,
            )?;
            by_profile
                .entry(item.edge.profile_id.as_str())
                .or_default()
                .push(item);
        }
    }

    let mut output = Vec::new();
    for (profile_id, edges) in by_profile {
        work.step(is_cancelled)?;
        let detected_cycles = cycle_rings_bounded(nodes, &edges, level, work, is_cancelled)?;
        for cycle in detected_cycles {
            work.step(is_cancelled)?;
            let ring = &cycle[..cycle.len() - 1];
            let mut has_source = false;
            let mut has_target = false;
            let mut start = None;
            for node in ring {
                work.step(is_cancelled)?;
                if source_ids.contains(node.as_str()) {
                    has_source = true;
                    if start.is_none_or(|current: &String| node < current) {
                        start = Some(node);
                    }
                }
                has_target |= target_ids.contains(node.as_str());
            }
            if !has_source || !has_target {
                continue;
            }
            let start = start.context("cycle start disappeared")?;
            let mut start_index = None;
            for (index, node) in ring.iter().enumerate() {
                work.step(is_cancelled)?;
                if node == start {
                    start_index = Some(index);
                    break;
                }
            }
            let start_index = start_index.context("cycle start disappeared")?;
            let mut node_path = Vec::new();
            for node in ring[start_index..].iter().chain(&ring[..start_index]) {
                work.step(is_cancelled)?;
                work.steps(node.len().saturating_add(1), is_cancelled)?;
                node_path.push(node.clone());
            }
            work.step(is_cancelled)?;
            work.steps(start.len().saturating_add(1), is_cancelled)?;
            node_path.push(start.clone());

            let mut path = Vec::new();
            let mut path_edges = Vec::new();
            for pair in node_path.windows(2) {
                work.step(is_cancelled)?;
                let mut selected: Option<&AdmittedEdge<'_>> = None;
                for item in &edges {
                    work.step(is_cancelled)?;
                    if item.edge.source == pair[0]
                        && item.edge.target == pair[1]
                        && selected.is_none_or(|current| item.edge.id < current.edge.id)
                    {
                        selected = Some(item);
                    }
                }
                let item = selected.with_context(|| {
                    format!(
                        "cycle query returned a step without an admitted edge: {} -> {}",
                        pair[0], pair[1]
                    )
                })?;
                work.step(is_cancelled)?;
                path.push(path_step_bounded(item.edge, work, is_cancelled)?);
                path_edges.push(item);
            }
            let violation = make_violation_bounded(
                rule,
                nodes,
                start,
                start,
                Some(profile_id),
                path,
                path_edges,
                format!(
                    "{} cycle contains {} dependency steps",
                    level.node_kind(),
                    node_path.len() - 1
                ),
                suppressions,
                work,
                is_cancelled,
            )?;
            work.step(is_cancelled)?;
            output.push(violation);
        }
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_depth_bounded(
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    sources: &[&NodeRecord],
    targets: &[&NodeRecord],
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PolicyViolation>> {
    let max = rule.threshold.context("depth rule threshold")?.max;
    let mut by_profile: BTreeMap<&str, Vec<&AdmittedEdge<'_>>> = BTreeMap::new();
    for item in admitted {
        work.step(is_cancelled)?;
        charge_ordered_collection_work(
            by_profile.len(),
            item.edge.profile_id.len(),
            work,
            is_cancelled,
        )?;
        by_profile
            .entry(item.edge.profile_id.as_str())
            .or_default()
            .push(item);
    }
    let mut output = Vec::new();

    for (profile_id, edges) in by_profile {
        work.step(is_cancelled)?;
        let adjacency = adjacency_bounded(&edges, work, is_cancelled)?;
        for source in sources {
            work.step(is_cancelled)?;
            work.steps(
                source.id.len().saturating_mul(2).saturating_add(1),
                is_cancelled,
            )?;
            let source_id = source.id.clone();
            let mut distance = BTreeMap::from([(source_id.clone(), 0_u64)]);
            let mut predecessor: HashMap<String, &AdmittedEdge<'_>> = HashMap::new();
            let mut queue = VecDeque::from([source_id]);
            while let Some(current) = queue.pop_front() {
                work.step(is_cancelled)?;
                work.steps(current.len().saturating_add(1), is_cancelled)?;
                let next_distance = distance[&current] + 1;
                for edge in adjacency.get(current.as_str()).into_iter().flatten() {
                    work.step(is_cancelled)?;
                    let target_id = edge.edge.target.as_str();
                    work.steps(target_id.len().saturating_add(1), is_cancelled)?;
                    charge_ordered_collection_work(
                        distance.len(),
                        target_id.len(),
                        work,
                        is_cancelled,
                    )?;
                    if !distance.contains_key(target_id) {
                        // Distance, predecessor, and queue each own a copy of
                        // the discovered node ID. Charge before cloning.
                        work.steps(target_id.len().saturating_mul(3), is_cancelled)?;
                        charge_ordered_collection_work(
                            predecessor.len(),
                            target_id.len(),
                            work,
                            is_cancelled,
                        )?;
                        let target_id = target_id.to_owned();
                        distance.insert(target_id.clone(), next_distance);
                        predecessor.insert(target_id.clone(), edge);
                        queue.push_back(target_id);
                    }
                }
            }

            for target in targets {
                work.step(is_cancelled)?;
                let Some(&actual) = distance.get(&target.id) else {
                    continue;
                };
                if actual <= max {
                    continue;
                }
                let path_edges = reconstruct_path_bounded(
                    &source.id,
                    &target.id,
                    &predecessor,
                    work,
                    is_cancelled,
                )?;
                let mut path = Vec::new();
                for item in &path_edges {
                    work.step(is_cancelled)?;
                    path.push(path_step_bounded(item.edge, work, is_cancelled)?);
                }
                let violation = make_violation_bounded(
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
                    work,
                    is_cancelled,
                )?;
                work.step(is_cancelled)?;
                output.push(violation);
            }
        }
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_fan_out_bounded(
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    sources: &[&NodeRecord],
    target_ids: &BTreeSet<&str>,
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PolicyViolation>> {
    let max = rule.threshold.context("fan-out rule threshold")?.max;
    let mut output = Vec::new();
    for source in sources {
        work.step(is_cancelled)?;
        let mut groups: BTreeMap<&str, BTreeMap<&str, &AdmittedEdge<'_>>> = BTreeMap::new();
        for item in admitted {
            work.step(is_cancelled)?;
            if item.edge.source != source.id || !target_ids.contains(item.edge.target.as_str()) {
                continue;
            }
            charge_ordered_collection_work(
                groups.len(),
                item.edge.profile_id.len(),
                work,
                is_cancelled,
            )?;
            let targets = groups.entry(item.edge.profile_id.as_str()).or_default();
            charge_ordered_collection_work(
                targets.len(),
                item.edge.target.len(),
                work,
                is_cancelled,
            )?;
            targets
                .entry(item.edge.target.as_str())
                .and_modify(|current| {
                    if item.edge.id < current.edge.id {
                        *current = item;
                    }
                })
                .or_insert(item);
        }
        for (profile_id, targets) in groups {
            work.step(is_cancelled)?;
            let count = u64::try_from(targets.len())?;
            if count <= max {
                continue;
            }
            let witness = overflow_witness_bounded(&targets, max, work, is_cancelled)?;
            let violation = make_violation_bounded(
                rule,
                nodes,
                &source.id,
                &witness.edge.target,
                Some(profile_id),
                vec![path_step_bounded(witness.edge, work, is_cancelled)?],
                vec![witness],
                format!("fan-out for {} is {count}, exceeding {max}", source.id),
                suppressions,
                work,
                is_cancelled,
            )?;
            work.step(is_cancelled)?;
            output.push(violation);
        }
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_fan_in_bounded(
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    source_ids: &BTreeSet<&str>,
    targets: &[&NodeRecord],
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PolicyViolation>> {
    let max = rule.threshold.context("fan-in rule threshold")?.max;
    let mut output = Vec::new();
    for target in targets {
        work.step(is_cancelled)?;
        let mut groups: BTreeMap<&str, BTreeMap<&str, &AdmittedEdge<'_>>> = BTreeMap::new();
        for item in admitted {
            work.step(is_cancelled)?;
            if item.edge.target != target.id || !source_ids.contains(item.edge.source.as_str()) {
                continue;
            }
            charge_ordered_collection_work(
                groups.len(),
                item.edge.profile_id.len(),
                work,
                is_cancelled,
            )?;
            let sources = groups.entry(item.edge.profile_id.as_str()).or_default();
            charge_ordered_collection_work(
                sources.len(),
                item.edge.source.len(),
                work,
                is_cancelled,
            )?;
            sources
                .entry(item.edge.source.as_str())
                .and_modify(|current| {
                    if item.edge.id < current.edge.id {
                        *current = item;
                    }
                })
                .or_insert(item);
        }
        for (profile_id, sources) in groups {
            work.step(is_cancelled)?;
            let count = u64::try_from(sources.len())?;
            if count <= max {
                continue;
            }
            let witness = overflow_witness_bounded(&sources, max, work, is_cancelled)?;
            let violation = make_violation_bounded(
                rule,
                nodes,
                &witness.edge.source,
                &target.id,
                Some(profile_id),
                vec![path_step_bounded(witness.edge, work, is_cancelled)?],
                vec![witness],
                format!("fan-in for {} is {count}, exceeding {max}", target.id),
                suppressions,
                work,
                is_cancelled,
            )?;
            work.step(is_cancelled)?;
            output.push(violation);
        }
    }
    Ok(output)
}

fn overflow_witness_bounded<'a>(
    entries: &'a BTreeMap<&str, &'a AdmittedEdge<'a>>,
    max: u64,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<&'a AdmittedEdge<'a>> {
    let index = usize::try_from(max)?;
    for (current, entry) in entries.values().enumerate() {
        work.step(is_cancelled)?;
        if current == index {
            return Ok(*entry);
        }
    }
    bail!("threshold overflow did not have a witness edge")
}

#[allow(dead_code)]
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
        charge_ordered_collection_work(
            adjacency.len(),
            edge.edge.source.len(),
            work,
            is_cancelled,
        )?;
        adjacency
            .entry(edge.edge.source.as_str())
            .or_default()
            .push(*edge);
    }
    for outgoing in adjacency.values_mut() {
        charge_sort_key_bytes_work(
            outgoing.len(),
            outgoing
                .iter()
                .map(|edge| edge.edge.target.len().saturating_add(edge.edge.id.len())),
            work,
            is_cancelled,
        )?;
        outgoing.sort_by(|left, right| {
            (&left.edge.target, &left.edge.id).cmp(&(&right.edge.target, &right.edge.id))
        });
    }
    Ok(adjacency)
}

#[allow(dead_code)]
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
        work.steps(current.len().saturating_add(1), is_cancelled)?;
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
    work.steps(source_id.len().saturating_add(1), is_cancelled)?;
    let source_node = nodes
        .get(source_id)
        .copied()
        .with_context(|| format!("policy source node {source_id:?} is missing"))?;
    work.step(is_cancelled)?;
    work.steps(target_id.len().saturating_add(1), is_cancelled)?;
    let target_node = nodes
        .get(target_id)
        .copied()
        .with_context(|| format!("policy target node {target_id:?} is missing"))?;
    let mut evidence = Vec::new();
    for item in &path_edges {
        work.step(is_cancelled)?;
        for span in &item.evidence {
            work.step(is_cancelled)?;
            work.steps(span.path.len().saturating_add(1), is_cancelled)?;
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
    work.steps(
        source_node
            .locator
            .len()
            .saturating_add(target_node.locator.len()),
        is_cancelled,
    )?;
    charge_violation_stable_id_work(
        &rule.id,
        source_id,
        target_id,
        profile_id,
        &dependency_path,
        work,
        is_cancelled,
    )?;
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

#[allow(dead_code)]
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
        if let Some(condition) = &scope.condition
            && evaluate_condition_bounded_inner(condition, context, false, work, is_cancelled)?
                != Some(true)
        {
            continue;
        }
        work.steps(
            resolved
                .suppression
                .id
                .len()
                .saturating_add(resolved.suppression.reason.len()),
            is_cancelled,
        )?;
        return Ok(Some(AppliedPolicySuppression {
            id: resolved.suppression.id.clone(),
            reason: resolved.suppression.reason.clone(),
        }));
    }
    Ok(None)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    charge_sort_key_bytes_work(
        matches.len(),
        matches.iter().map(|node| node.id.len()),
        work,
        is_cancelled,
    )?;
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
        charge_ordered_collection_work(ids.len(), node.id.len(), work, is_cancelled)?;
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
        work.steps(node.id.len().saturating_add(1), is_cancelled)?;
        charge_ordered_collection_work(ids.len(), node.id.len(), work, is_cancelled)?;
        ids.insert(node.id.clone());
    }
    Ok(ids)
}

#[allow(dead_code)]
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
    if !pattern_matches_bounded(
        selector.match_kind,
        &selector.value,
        value,
        work,
        is_cancelled,
    )? {
        return Ok(false);
    }
    for exclude in &selector.exclude {
        if let Some(value) = selector_field(node, exclude.field)
            && pattern_matches_bounded(
                exclude.match_kind,
                &exclude.value,
                value,
                work,
                is_cancelled,
            )?
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

#[allow(dead_code)]
fn optional_profile_matches(filter: &PolicyProfileFilter, profile_id: Option<&str>) -> bool {
    profile_id.map_or_else(
        || filter == &PolicyProfileFilter::default(),
        |profile_id| profile_matches(filter, profile_id),
    )
}

#[allow(dead_code)]
fn policy_entity(node: &NodeRecord, kind: PolicySelectorKind) -> PolicyEntity {
    PolicyEntity {
        id: node.id.clone(),
        kind,
        locator: node.locator.clone(),
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
        if pattern_matches_bounded(
            pattern.match_kind,
            &pattern.value,
            value,
            work,
            is_cancelled,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn pattern_matches(kind: PolicyMatchKind, pattern: &str, value: &str) -> bool {
    match kind {
        PolicyMatchKind::Exact => value == pattern,
        PolicyMatchKind::Prefix => value.starts_with(pattern),
        PolicyMatchKind::Glob => glob_matches(pattern, value),
    }
}

fn pattern_matches_bounded(
    kind: PolicyMatchKind,
    pattern: &str,
    value: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool> {
    work.step(is_cancelled)?;
    match kind {
        PolicyMatchKind::Exact => {
            if value.len() != pattern.len() {
                return Ok(false);
            }
            literal_prefix_matches_bounded(pattern, value, work, is_cancelled)
        }
        PolicyMatchKind::Prefix => {
            if value.len() < pattern.len() {
                return Ok(false);
            }
            literal_prefix_matches_bounded(pattern, value, work, is_cancelled)
        }
        PolicyMatchKind::Glob => glob_matches_bounded(pattern, value, work, is_cancelled),
    }
}

fn literal_prefix_matches_bounded(
    pattern: &str,
    value: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool> {
    for (expected, actual) in pattern.bytes().zip(value.bytes()) {
        work.step(is_cancelled)?;
        if expected != actual {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(dead_code)]
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

/// Match a policy glob without recursion and account for every character/state
/// visited. RuntimeBoundary selectors use this function because a
/// user-controlled locator can otherwise create an unbounded recursion and a
/// quadratic search without any cancellation point.
fn glob_matches_bounded(
    pattern: &str,
    value: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool> {
    let mut pattern_chars = Vec::new();
    for character in pattern.chars() {
        work.step(is_cancelled)?;
        pattern_chars.push(character);
    }
    let mut value_chars = Vec::new();
    for character in value.chars() {
        work.step(is_cancelled)?;
        value_chars.push(character);
    }

    let mut pending = vec![(0_usize, 0_usize)];
    let mut visited = HashMap::new();
    while let Some((pattern_index, value_index)) = pending.pop() {
        work.step(is_cancelled)?;
        if visited.insert((pattern_index, value_index), true).is_some() {
            continue;
        }
        if pattern_index == pattern_chars.len() {
            if value_index == value_chars.len() {
                return Ok(true);
            }
            continue;
        }

        if pattern_chars[pattern_index] == '*' {
            let double = pattern_chars.get(pattern_index + 1) == Some(&'*');
            let next_pattern = pattern_index + usize::from(double) + 1;
            work.step(is_cancelled)?;
            pending.push((next_pattern, value_index));
            if double && pattern_chars.get(next_pattern) == Some(&'/') {
                work.step(is_cancelled)?;
                pending.push((next_pattern + 1, value_index));
            }
            if value_index < value_chars.len() && (double || value_chars[value_index] != '/') {
                work.step(is_cancelled)?;
                pending.push((pattern_index, value_index + 1));
            }
        } else if value_index < value_chars.len()
            && ((pattern_chars[pattern_index] == '?' && value_chars[value_index] != '/')
                || pattern_chars[pattern_index] == value_chars[value_index])
        {
            work.step(is_cancelled)?;
            pending.push((pattern_index + 1, value_index + 1));
        }
    }
    Ok(false)
}

fn edge_context_bounded(
    edge: &EdgeRecord,
    profile: Option<&ProfileRecord>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<String, Value>> {
    fn insert_string(
        context: &mut BTreeMap<String, Value>,
        key: &str,
        value: &str,
        work: &mut PolicyEvaluationWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<()> {
        work.steps(
            key.len().saturating_add(value.len()).saturating_add(1),
            is_cancelled,
        )?;
        charge_ordered_collection_work(context.len(), key.len(), work, is_cancelled)?;
        context.insert(key.to_owned(), Value::String(value.to_owned()));
        Ok(())
    }
    fn insert_bool(
        context: &mut BTreeMap<String, Value>,
        key: &str,
        value: bool,
        work: &mut PolicyEvaluationWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<()> {
        work.steps(key.len().saturating_add(1), is_cancelled)?;
        charge_ordered_collection_work(context.len(), key.len(), work, is_cancelled)?;
        context.insert(key.to_owned(), Value::Bool(value));
        Ok(())
    }

    let mut context = BTreeMap::new();
    if let Some(profile) = profile {
        merge_object_bounded(&mut context, &profile.environment, work, is_cancelled)?;
        merge_object_bounded(&mut context, &profile.properties, work, is_cancelled)?;
        insert_string(
            &mut context,
            "language",
            &profile.language,
            work,
            is_cancelled,
        )?;
        if let Some(target) = &profile.target {
            insert_string(&mut context, "target", target, work, is_cancelled)?;
        }
        if let Some(command) = &profile.command {
            insert_string(&mut context, "command", command, work, is_cancelled)?;
        }
        let mut features = Vec::new();
        for feature in &profile.features {
            work.steps(feature.len().saturating_add(1), is_cancelled)?;
            features.push(Value::String(feature.clone()));
        }
        work.steps("features".len().saturating_add(1), is_cancelled)?;
        charge_ordered_collection_work(context.len(), "features".len(), work, is_cancelled)?;
        context.insert("features".to_owned(), Value::Array(features));
    }
    insert_string(
        &mut context,
        "profile",
        &edge.profile_id,
        work,
        is_cancelled,
    )?;
    insert_string(
        &mut context,
        "profile_id",
        &edge.profile_id,
        work,
        is_cancelled,
    )?;
    insert_string(&mut context, "phase", &edge.phase, work, is_cancelled)?;
    insert_string(
        &mut context,
        "environment",
        &edge.environment,
        work,
        is_cancelled,
    )?;
    insert_string(
        &mut context,
        "precision",
        &edge.precision,
        work,
        is_cancelled,
    )?;
    insert_string(
        &mut context,
        "resolution_status",
        &edge.resolution_status,
        work,
        is_cancelled,
    )?;
    insert_bool(
        &mut context,
        "generated",
        edge.generated,
        work,
        is_cancelled,
    )?;
    Ok(context)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

const MAX_EDGE_CONDITION_DEPTH: usize = 16;
const MAX_EDGE_CONDITION_JSON_DEPTH: usize = 2 * MAX_EDGE_CONDITION_DEPTH + 2;

enum ConditionParseFrame<'a> {
    Visit {
        value: &'a Value,
        depth: usize,
    },
    Aggregate {
        any: bool,
        children: &'a [Value],
        depth: usize,
        next: usize,
        awaiting_child: bool,
        values: Vec<PolicyCondition>,
    },
    Not,
}

/// Decode an edge condition without recursively walking attacker-controlled
/// JSON.  Graph snapshots normally contain protocol-validated conditions, but
/// policy evaluation also accepts snapshots loaded from older stores and test
/// fixtures.  Keeping the parser iterative makes a malformed/deep condition
/// consume the shared policy budget instead of growing the Rust call stack.
/// The depth ceiling matches `PolicyCondition::validate_inner`: leaf operators
/// may occur at depth 16, while an aggregate or `not` operator at that depth
/// is rejected before its child can deepen the tree.
fn parse_condition_bounded(
    value: &Value,
    edge_id: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyCondition> {
    let mut frames = vec![ConditionParseFrame::Visit { value, depth: 0 }];
    let mut values = Vec::new();

    while let Some(frame) = frames.pop() {
        match frame {
            ConditionParseFrame::Visit { value, depth } => {
                work.step(is_cancelled)?;
                let object = value
                    .as_object()
                    .with_context(|| format!("edge {edge_id:?} has an invalid policy condition"))?;
                let operation = object
                    .get("op")
                    .and_then(Value::as_str)
                    .with_context(|| format!("edge {edge_id:?} has an invalid policy condition"))?;
                if depth >= MAX_EDGE_CONDITION_DEPTH && matches!(operation, "all" | "any" | "not") {
                    return Err(PolicyEvaluationWorkExhausted.into());
                }
                match operation {
                    "all" | "any" => {
                        require_condition_fields(
                            object,
                            &["op", "conditions"],
                            edge_id,
                            work,
                            is_cancelled,
                        )?;
                        let children = object
                            .get("conditions")
                            .and_then(Value::as_array)
                            .with_context(|| {
                                format!("edge {edge_id:?} has an invalid policy condition")
                            })?;
                        work.steps(children.len(), is_cancelled)?;
                        if children.len() > 255 {
                            return Err(PolicyEvaluationWorkExhausted.into());
                        }
                        frames.push(ConditionParseFrame::Aggregate {
                            any: operation == "any",
                            children,
                            depth,
                            next: 0,
                            awaiting_child: false,
                            values: Vec::new(),
                        });
                    }
                    "not" => {
                        require_condition_fields(
                            object,
                            &["op", "condition"],
                            edge_id,
                            work,
                            is_cancelled,
                        )?;
                        let child = object.get("condition").with_context(|| {
                            format!("edge {edge_id:?} has an invalid policy condition")
                        })?;
                        frames.push(ConditionParseFrame::Not);
                        frames.push(ConditionParseFrame::Visit {
                            value: child,
                            depth: depth.saturating_add(1),
                        });
                    }
                    "eq" => {
                        require_condition_fields(
                            object,
                            &["op", "key", "value"],
                            edge_id,
                            work,
                            is_cancelled,
                        )?;
                        let key = condition_key_bounded(object, edge_id, work, is_cancelled)?;
                        let value = condition_value_bounded(
                            object.get("value").with_context(|| {
                                format!("edge {edge_id:?} has an invalid policy condition")
                            })?,
                            edge_id,
                            work,
                            is_cancelled,
                        )?;
                        values.push(PolicyCondition::Eq { key, value });
                    }
                    "in" => {
                        require_condition_fields(
                            object,
                            &["op", "key", "values"],
                            edge_id,
                            work,
                            is_cancelled,
                        )?;
                        let key = condition_key_bounded(object, edge_id, work, is_cancelled)?;
                        let raw_values = object
                            .get("values")
                            .and_then(Value::as_array)
                            .with_context(|| {
                                format!("edge {edge_id:?} has an invalid policy condition")
                            })?;
                        work.steps(raw_values.len(), is_cancelled)?;
                        if raw_values.len() > 128 {
                            return Err(PolicyEvaluationWorkExhausted.into());
                        }
                        let mut condition_values = Vec::new();
                        for value in raw_values {
                            condition_values.push(condition_value_bounded(
                                value,
                                edge_id,
                                work,
                                is_cancelled,
                            )?);
                        }
                        values.push(PolicyCondition::In {
                            key,
                            values: condition_values,
                        });
                    }
                    "defined" => {
                        require_condition_fields(
                            object,
                            &["op", "key"],
                            edge_id,
                            work,
                            is_cancelled,
                        )?;
                        values.push(PolicyCondition::Defined {
                            key: condition_key_bounded(object, edge_id, work, is_cancelled)?,
                        });
                    }
                    _ => {
                        bail!("edge {edge_id:?} has an invalid policy condition")
                    }
                }
            }
            ConditionParseFrame::Aggregate {
                any,
                children,
                depth,
                mut next,
                awaiting_child,
                values: mut conditions,
            } => {
                if awaiting_child {
                    conditions.push(values.pop().with_context(|| {
                        format!("edge {edge_id:?} has an invalid policy condition")
                    })?);
                }
                if next < children.len() {
                    let child = &children[next];
                    next += 1;
                    frames.push(ConditionParseFrame::Aggregate {
                        any,
                        children,
                        depth,
                        next,
                        awaiting_child: true,
                        values: conditions,
                    });
                    frames.push(ConditionParseFrame::Visit {
                        value: child,
                        depth: depth.saturating_add(1),
                    });
                } else {
                    values.push(if any {
                        PolicyCondition::Any { conditions }
                    } else {
                        PolicyCondition::All { conditions }
                    });
                }
            }
            ConditionParseFrame::Not => {
                let condition = values
                    .pop()
                    .with_context(|| format!("edge {edge_id:?} has an invalid policy condition"))?;
                values.push(PolicyCondition::Not {
                    condition: Box::new(condition),
                });
            }
        }
    }

    values
        .pop()
        .filter(|_| values.is_empty())
        .with_context(|| format!("edge {edge_id:?} has an invalid policy condition"))
}

fn require_condition_fields(
    object: &serde_json::Map<String, Value>,
    expected: &[&str],
    edge_id: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    if object.len() != expected.len() {
        bail!("edge {edge_id:?} has an invalid policy condition");
    }
    for key in object.keys() {
        work.step(is_cancelled)?;
        if !expected.contains(&key.as_str()) {
            bail!("edge {edge_id:?} has an invalid policy condition");
        }
    }
    Ok(())
}

fn condition_key_bounded(
    object: &serde_json::Map<String, Value>,
    edge_id: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<String> {
    let key = object
        .get("key")
        .and_then(Value::as_str)
        .with_context(|| format!("edge {edge_id:?} has an invalid policy condition"))?;
    if key.is_empty() {
        bail!("edge {edge_id:?} has an invalid policy condition");
    }
    if key.len() > 128 {
        return Err(PolicyEvaluationWorkExhausted.into());
    }
    work.steps(key.len().saturating_add(1), is_cancelled)?;
    Ok(key.to_owned())
}

fn condition_value_bounded(
    value: &Value,
    edge_id: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Value> {
    charge_condition_value_work(value, work, is_cancelled)?;
    if !(value.is_null() || value.is_boolean() || value.is_number() || value.is_string()) {
        bail!("edge {edge_id:?} has an invalid policy condition");
    }
    if let Value::String(value) = value
        && value.chars().count() > 1024
    {
        return Err(PolicyEvaluationWorkExhausted.into());
    }
    Ok(value.clone())
}

fn charge_condition_value_work(
    value: &Value,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    work.step(is_cancelled)?;
    if let Some(value) = value.as_str() {
        work.steps(value.len(), is_cancelled)?;
    }
    Ok(())
}

fn condition_value_serialized_work(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(value) => {
            if *value {
                4
            } else {
                5
            }
        }
        // serde_json numbers are scalar values in the default build. Keep a
        // conservative fixed charge without serializing/allocating first.
        Value::Number(_) => 128,
        // Quotes, backslashes, and escaped UTF-8 code points can expand a
        // string; this upper bound is intentionally conservative.
        Value::String(value) => value.len().saturating_mul(6).saturating_add(2),
        Value::Array(_) | Value::Object(_) => 0,
    }
}

fn condition_string_serialized_work(value: &str) -> usize {
    value.len().saturating_mul(6).saturating_add(2)
}

enum ConditionEvalFrame<'a> {
    Visit(&'a PolicyCondition),
    Aggregate {
        any: bool,
        conditions: &'a [PolicyCondition],
        next: usize,
        awaiting_child: bool,
        saw_true: bool,
        saw_false: bool,
        saw_unknown: bool,
    },
    Not,
}

fn evaluate_edge_condition_bounded(
    condition: &PolicyCondition,
    context: &BTreeMap<String, Value>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<bool>> {
    evaluate_condition_bounded_inner(condition, context, true, work, is_cancelled)
}

fn evaluate_condition_bounded_inner(
    condition: &PolicyCondition,
    context: &BTreeMap<String, Value>,
    edge_semantics: bool,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<bool>> {
    let mut frames = vec![ConditionEvalFrame::Visit(condition)];
    let mut values = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            ConditionEvalFrame::Visit(condition) => {
                work.step(is_cancelled)?;
                match condition {
                    PolicyCondition::All { conditions } | PolicyCondition::Any { conditions } => {
                        frames.push(ConditionEvalFrame::Aggregate {
                            any: matches!(condition, PolicyCondition::Any { .. }),
                            conditions,
                            next: 0,
                            awaiting_child: false,
                            saw_true: false,
                            saw_false: false,
                            saw_unknown: false,
                        })
                    }
                    PolicyCondition::Not { condition } => {
                        frames.push(ConditionEvalFrame::Not);
                        frames.push(ConditionEvalFrame::Visit(condition));
                    }
                    PolicyCondition::Eq { key, value } => {
                        values.push(
                            if let Some(actual) =
                                lookup_context_bounded(context, key, work, is_cancelled)?
                            {
                                Some(condition_values_equal_bounded(
                                    actual,
                                    value,
                                    work,
                                    is_cancelled,
                                )?)
                            } else {
                                None
                            },
                        );
                    }
                    PolicyCondition::In {
                        key,
                        values: expected,
                    } => {
                        let Some(actual) =
                            lookup_context_bounded(context, key, work, is_cancelled)?
                        else {
                            values.push(None);
                            continue;
                        };
                        let mut matched = false;
                        for value in expected {
                            if condition_values_equal_bounded(actual, value, work, is_cancelled)? {
                                matched = true;
                                break;
                            }
                        }
                        values.push(Some(matched));
                    }
                    PolicyCondition::Defined { key } => {
                        let value = lookup_context_bounded(context, key, work, is_cancelled)?;
                        values.push(if edge_semantics {
                            value.map(|value| !value.is_null())
                        } else {
                            Some(value.is_some_and(|value| !value.is_null()))
                        });
                    }
                }
            }
            ConditionEvalFrame::Aggregate {
                any,
                conditions,
                mut next,
                awaiting_child,
                mut saw_true,
                mut saw_false,
                mut saw_unknown,
            } => {
                if awaiting_child {
                    match values
                        .pop()
                        .context("bounded condition evaluation lost a child")?
                    {
                        Some(true) => saw_true = true,
                        Some(false) => saw_false = true,
                        None => saw_unknown = true,
                    }
                }
                if next < conditions.len() {
                    let child = &conditions[next];
                    next += 1;
                    frames.push(ConditionEvalFrame::Aggregate {
                        any,
                        conditions,
                        next,
                        awaiting_child: true,
                        saw_true,
                        saw_false,
                        saw_unknown,
                    });
                    frames.push(ConditionEvalFrame::Visit(child));
                } else {
                    values.push(if any {
                        if saw_true {
                            Some(true)
                        } else if saw_unknown {
                            None
                        } else {
                            Some(false)
                        }
                    } else if saw_false {
                        Some(false)
                    } else if saw_unknown {
                        None
                    } else {
                        Some(true)
                    });
                }
            }
            ConditionEvalFrame::Not => {
                let value = values
                    .pop()
                    .context("bounded condition evaluation lost a not child")?;
                values.push(value.map(|value| !value));
            }
        }
    }
    values
        .pop()
        .filter(|_| values.is_empty())
        .context("bounded condition evaluation did not produce one result")
}

fn lookup_context_bounded<'a>(
    context: &'a BTreeMap<String, Value>,
    key: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<&'a Value>> {
    work.steps(key.len().saturating_add(1), is_cancelled)?;
    if let Some(value) = context.get(key) {
        return Ok(Some(value));
    }
    let mut segments = key.split('.');
    let Some(first) = segments.next() else {
        return Ok(None);
    };
    let mut value = context.get(first);
    for segment in segments {
        work.steps(segment.len().saturating_add(1), is_cancelled)?;
        value = value.and_then(|value| value.get(segment));
    }
    Ok(value)
}

enum ConditionFactsFrame<'a> {
    Visit(&'a PolicyCondition),
    All {
        conditions: &'a [PolicyCondition],
        next: usize,
    },
}

fn add_condition_facts_bounded(
    condition: &PolicyCondition,
    context: &mut BTreeMap<String, Value>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    let mut frames = vec![ConditionFactsFrame::Visit(condition)];
    while let Some(frame) = frames.pop() {
        match frame {
            ConditionFactsFrame::Visit(condition) => {
                work.step(is_cancelled)?;
                match condition {
                    PolicyCondition::All { conditions } => {
                        frames.push(ConditionFactsFrame::All {
                            conditions,
                            next: 0,
                        });
                    }
                    PolicyCondition::Eq { key, value } => {
                        work.steps(key.len().saturating_add(1), is_cancelled)?;
                        charge_condition_value_work(value, work, is_cancelled)?;
                        charge_ordered_collection_work(
                            context.len(),
                            key.len(),
                            work,
                            is_cancelled,
                        )?;
                        context.entry(key.clone()).or_insert_with(|| value.clone());
                    }
                    PolicyCondition::In { key, values } if values.len() == 1 => {
                        work.steps(key.len().saturating_add(1), is_cancelled)?;
                        charge_condition_value_work(&values[0], work, is_cancelled)?;
                        charge_ordered_collection_work(
                            context.len(),
                            key.len(),
                            work,
                            is_cancelled,
                        )?;
                        context
                            .entry(key.clone())
                            .or_insert_with(|| values[0].clone());
                    }
                    PolicyCondition::Defined { key } => {
                        work.steps(key.len().saturating_add(1), is_cancelled)?;
                        charge_ordered_collection_work(
                            context.len(),
                            key.len(),
                            work,
                            is_cancelled,
                        )?;
                        context.entry(key.clone()).or_insert(Value::Bool(true));
                    }
                    PolicyCondition::Any { .. }
                    | PolicyCondition::Not { .. }
                    | PolicyCondition::In { .. } => {}
                }
            }
            ConditionFactsFrame::All {
                conditions,
                mut next,
            } => {
                if next < conditions.len() {
                    let child = &conditions[next];
                    next += 1;
                    frames.push(ConditionFactsFrame::All { conditions, next });
                    frames.push(ConditionFactsFrame::Visit(child));
                }
            }
        }
    }
    Ok(())
}

enum ConditionCanonicalizeFrame<'a> {
    Visit(&'a PolicyCondition),
    Aggregate {
        any: bool,
        conditions: &'a [PolicyCondition],
        next: usize,
        awaiting_child: bool,
        values: Vec<PolicyCondition>,
    },
    Not,
}

fn canonical_condition_bounded(
    condition: &PolicyCondition,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyCondition> {
    let mut frames = vec![ConditionCanonicalizeFrame::Visit(condition)];
    let mut values = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            ConditionCanonicalizeFrame::Visit(condition) => {
                work.step(is_cancelled)?;
                match condition {
                    PolicyCondition::All { conditions } | PolicyCondition::Any { conditions } => {
                        frames.push(ConditionCanonicalizeFrame::Aggregate {
                            any: matches!(condition, PolicyCondition::Any { .. }),
                            conditions,
                            next: 0,
                            awaiting_child: false,
                            values: Vec::new(),
                        });
                    }
                    PolicyCondition::Not { condition } => {
                        frames.push(ConditionCanonicalizeFrame::Not);
                        frames.push(ConditionCanonicalizeFrame::Visit(condition));
                    }
                    PolicyCondition::Eq { key, value } => {
                        work.steps(key.len().saturating_add(1), is_cancelled)?;
                        charge_condition_value_work(value, work, is_cancelled)?;
                        values.push(PolicyCondition::Eq {
                            key: key.clone(),
                            value: value.clone(),
                        });
                    }
                    PolicyCondition::In {
                        key,
                        values: expected,
                    } => {
                        work.steps(key.len().saturating_add(1), is_cancelled)?;
                        let mut keyed = Vec::new();
                        for value in expected {
                            charge_condition_value_work(value, work, is_cancelled)?;
                            if !(value.is_null()
                                || value.is_boolean()
                                || value.is_number()
                                || value.is_string())
                            {
                                bail!("edge condition value must be a JSON primitive");
                            }
                            work.steps(condition_value_serialized_work(value), is_cancelled)?;
                            let sort_key = serde_json::to_string(value)?;
                            work.steps(sort_key.len().saturating_add(1), is_cancelled)?;
                            keyed.push((sort_key, value.clone()));
                        }
                        charge_condition_key_sort_work(&keyed, work, is_cancelled)?;
                        keyed.sort_by(|left, right| left.0.cmp(&right.0));
                        keyed.dedup_by(|left, right| left.0 == right.0);
                        let expected = keyed
                            .into_iter()
                            .map(|(_, value)| value)
                            .collect::<Vec<_>>();
                        if let [value] = expected.as_slice() {
                            values.push(PolicyCondition::Eq {
                                key: key.clone(),
                                value: value.clone(),
                            });
                        } else {
                            values.push(PolicyCondition::In {
                                key: key.clone(),
                                values: expected,
                            });
                        }
                    }
                    PolicyCondition::Defined { key } => {
                        work.steps(key.len().saturating_add(1), is_cancelled)?;
                        values.push(PolicyCondition::Defined { key: key.clone() });
                    }
                }
            }
            ConditionCanonicalizeFrame::Aggregate {
                any,
                conditions,
                mut next,
                awaiting_child,
                values: mut children,
            } => {
                if awaiting_child {
                    children.push(
                        values
                            .pop()
                            .context("bounded condition canonicalization lost a child")?,
                    );
                }
                if next < conditions.len() {
                    let child = &conditions[next];
                    next += 1;
                    frames.push(ConditionCanonicalizeFrame::Aggregate {
                        any,
                        conditions,
                        next,
                        awaiting_child: true,
                        values: children,
                    });
                    frames.push(ConditionCanonicalizeFrame::Visit(child));
                } else {
                    values.push(canonicalize_condition_operator_bounded(
                        any,
                        children,
                        work,
                        is_cancelled,
                    )?);
                }
            }
            ConditionCanonicalizeFrame::Not => {
                let condition = values
                    .pop()
                    .context("bounded condition canonicalization lost a not child")?;
                if let PolicyCondition::Not { condition } = condition {
                    values.push(*condition);
                } else {
                    values.push(PolicyCondition::Not {
                        condition: Box::new(condition),
                    });
                }
            }
        }
    }
    values
        .pop()
        .filter(|_| values.is_empty())
        .context("bounded condition canonicalization did not produce one result")
}

fn canonicalize_condition_operator_bounded(
    any: bool,
    values: Vec<PolicyCondition>,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyCondition> {
    let mut flattened = Vec::new();
    for condition in values {
        work.step(is_cancelled)?;
        match (any, condition) {
            (false, PolicyCondition::All { conditions }) if conditions.is_empty() => {}
            (true, PolicyCondition::All { conditions }) if conditions.is_empty() => {
                return Ok(PolicyCondition::All {
                    conditions: Vec::new(),
                });
            }
            (false, PolicyCondition::All { conditions })
            | (true, PolicyCondition::Any { conditions }) => flattened.extend(conditions),
            (_, condition) => flattened.push(condition),
        }
    }

    let mut keyed = Vec::new();
    for condition in flattened {
        let key = condition_sort_key_bounded(&condition, work, is_cancelled)?;
        keyed.push((key, condition));
    }
    charge_condition_key_sort_work(&keyed, work, is_cancelled)?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    let conditions = keyed
        .into_iter()
        .map(|(_, condition)| condition)
        .collect::<Vec<_>>();
    match (any, conditions.len()) {
        (_, 0) if any => Ok(PolicyCondition::Any {
            conditions: Vec::new(),
        }),
        (_, 0) => Ok(PolicyCondition::All {
            conditions: Vec::new(),
        }),
        (_, 1) => Ok(conditions.into_iter().next().expect("length checked")),
        (true, _) => Ok(PolicyCondition::Any { conditions }),
        (false, _) => Ok(PolicyCondition::All { conditions }),
    }
}

fn charge_condition_sort_work(
    len: usize,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    if len <= 1 {
        return Ok(());
    }
    let rounds = usize::BITS as usize - (len - 1).leading_zeros() as usize;
    for _ in 0..len.saturating_mul(rounds) {
        work.step(is_cancelled)?;
    }
    Ok(())
}

fn charge_condition_key_sort_work<T>(
    keyed: &[(String, T)],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    charge_condition_sort_work(keyed.len(), work, is_cancelled)?;
    if keyed.len() <= 1 {
        return Ok(());
    }
    let rounds = usize::BITS as usize - (keyed.len() - 1).leading_zeros() as usize;
    for (key, _) in keyed {
        work.steps(key.len().saturating_mul(rounds), is_cancelled)?;
    }
    Ok(())
}

enum ConditionRenderFrame<'a> {
    Visit(&'a PolicyCondition),
    List {
        conditions: &'a [PolicyCondition],
        next: usize,
    },
    Close(&'static str),
}

fn append_condition_string_bounded(
    output: &mut String,
    value: &str,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    work.steps(value.len().saturating_add(1), is_cancelled)?;
    work.steps(condition_string_serialized_work(value), is_cancelled)?;
    let encoded = serde_json::to_string(value)?;
    work.steps(encoded.len().saturating_add(1), is_cancelled)?;
    output.push_str(&encoded);
    Ok(())
}

fn append_condition_value_bounded(
    output: &mut String,
    value: &Value,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    charge_condition_value_work(value, work, is_cancelled)?;
    work.steps(condition_value_serialized_work(value), is_cancelled)?;
    let encoded = serde_json::to_string(value)?;
    work.steps(encoded.len().saturating_add(1), is_cancelled)?;
    output.push_str(&encoded);
    Ok(())
}

/// Produce the same JSON ordering key used by `Condition::canonicalized`, but
/// with an explicit stack.  Canonical ordering is observable in policy output,
/// so replacing it with pointer/order-dependent sorting would be a regression.
fn condition_sort_key_bounded(
    condition: &PolicyCondition,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<String> {
    let mut frames = vec![ConditionRenderFrame::Visit(condition)];
    let mut output = String::new();
    while let Some(frame) = frames.pop() {
        match frame {
            ConditionRenderFrame::Visit(condition) => {
                work.step(is_cancelled)?;
                match condition {
                    PolicyCondition::All { conditions } => {
                        output.push_str(r#"{"op":"all","conditions":["#);
                        frames.push(ConditionRenderFrame::Close("]}"));
                        frames.push(ConditionRenderFrame::List {
                            conditions,
                            next: 0,
                        });
                    }
                    PolicyCondition::Any { conditions } => {
                        output.push_str(r#"{"op":"any","conditions":["#);
                        frames.push(ConditionRenderFrame::Close("]}"));
                        frames.push(ConditionRenderFrame::List {
                            conditions,
                            next: 0,
                        });
                    }
                    PolicyCondition::Not { condition } => {
                        output.push_str(r#"{"op":"not","condition":"#);
                        frames.push(ConditionRenderFrame::Close("}"));
                        frames.push(ConditionRenderFrame::Visit(condition));
                    }
                    PolicyCondition::Eq { key, value } => {
                        output.push_str(r#"{"op":"eq","key":"#);
                        append_condition_string_bounded(&mut output, key, work, is_cancelled)?;
                        output.push_str(r#","value":"#);
                        append_condition_value_bounded(&mut output, value, work, is_cancelled)?;
                        output.push('}');
                    }
                    PolicyCondition::In { key, values } => {
                        output.push_str(r#"{"op":"in","key":"#);
                        append_condition_string_bounded(&mut output, key, work, is_cancelled)?;
                        output.push_str(r#","values":["#);
                        for (index, value) in values.iter().enumerate() {
                            if index > 0 {
                                output.push(',');
                            }
                            append_condition_value_bounded(&mut output, value, work, is_cancelled)?;
                        }
                        output.push_str("]}");
                    }
                    PolicyCondition::Defined { key } => {
                        output.push_str(r#"{"op":"defined","key":"#);
                        append_condition_string_bounded(&mut output, key, work, is_cancelled)?;
                        output.push('}');
                    }
                }
            }
            ConditionRenderFrame::List {
                conditions,
                mut next,
            } => {
                if next < conditions.len() {
                    if next > 0 {
                        output.push(',');
                    }
                    let child = &conditions[next];
                    next += 1;
                    frames.push(ConditionRenderFrame::List { conditions, next });
                    frames.push(ConditionRenderFrame::Visit(child));
                }
            }
            ConditionRenderFrame::Close(value) => output.push_str(value),
        }
    }
    Ok(output)
}

fn combined_condition_bounded(
    edges: &[&AdmittedEdge<'_>],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyCondition> {
    let mut conditions = BTreeMap::<String, PolicyCondition>::new();
    for edge in edges {
        work.step(is_cancelled)?;
        let condition = canonical_condition_bounded(&edge.condition, work, is_cancelled)?;
        let key = condition_sort_key_bounded(&condition, work, is_cancelled)?;
        charge_ordered_collection_work(conditions.len(), key.len(), work, is_cancelled)?;
        conditions.insert(key, condition);
    }
    work.steps(conditions.len(), is_cancelled)?;
    let conditions = conditions.into_values().collect::<Vec<_>>();
    let condition =
        canonical_condition_bounded(&PolicyCondition::All { conditions }, work, is_cancelled)?;
    validate_combined_condition_depth_bounded(&condition, work, is_cancelled)?;
    Ok(condition)
}

fn validate_combined_condition_depth_bounded(
    condition: &PolicyCondition,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    let mut pending = vec![(condition, 0_usize)];
    while let Some((condition, depth)) = pending.pop() {
        work.step(is_cancelled)?;
        match condition {
            PolicyCondition::All { conditions } | PolicyCondition::Any { conditions } => {
                if depth >= MAX_EDGE_CONDITION_DEPTH {
                    return Err(CombinedPolicyConditionDepthExceeded.into());
                }
                work.steps(conditions.len(), is_cancelled)?;
                for child in conditions.iter().rev() {
                    pending.push((child, depth.saturating_add(1)));
                }
            }
            PolicyCondition::Not { condition } => {
                if depth >= MAX_EDGE_CONDITION_DEPTH {
                    return Err(CombinedPolicyConditionDepthExceeded.into());
                }
                pending.push((condition, depth.saturating_add(1)));
            }
            PolicyCondition::Eq { .. }
            | PolicyCondition::In { .. }
            | PolicyCondition::Defined { .. } => {}
        }
    }
    Ok(())
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

fn condition_values_equal_bounded(
    left: &Value,
    right: &Value,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool> {
    charge_condition_value_work(left, work, is_cancelled)?;
    charge_condition_value_work(right, work, is_cancelled)?;
    Ok(condition_values_equal(left, right))
}

#[allow(dead_code)]
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
    let mut records_by_priority = Vec::new();
    for record in records {
        work.step(is_cancelled)?;
        records_by_priority.push(*record);
    }
    charge_sort_key_bytes_work(
        records_by_priority.len(),
        records_by_priority
            .iter()
            .map(|record| record.kind.len().saturating_add(record.path.len())),
        work,
        is_cancelled,
    )?;
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
        work.steps(
            record.kind.len().saturating_add(record.path.len()),
            is_cancelled,
        )?;
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    charge_sort_key_bytes_work(
        evidence.len(),
        evidence.iter().map(|span| {
            span.path
                .len()
                .saturating_add(evidence_kind_name(span.kind).len())
        }),
        work,
        is_cancelled,
    )?;
    work.steps(evidence.len(), is_cancelled)?;
    canonicalize_evidence(evidence);
    Ok(())
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn canonical_condition(condition: &PolicyCondition) -> Result<PolicyCondition> {
    Ok(serde_json::from_value(serde_json::to_value(
        condition.canonicalized(),
    )?)?)
}

fn serialized_names_bounded<T: Serialize>(
    values: &[T],
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeSet<String>> {
    let mut output = BTreeSet::new();
    for value in values {
        work.step(is_cancelled)?;
        let serialized = serde_json::to_value(value)?;
        let name = serialized
            .as_str()
            .context("policy enum did not serialize as a string")?;
        work.steps(name.len().saturating_add(1), is_cancelled)?;
        charge_ordered_collection_work(output.len(), name.len(), work, is_cancelled)?;
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

fn path_step_bounded(
    edge: &EdgeRecord,
    work: &mut PolicyEvaluationWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<PolicyPathStep> {
    work.steps(
        edge.source
            .len()
            .saturating_add(edge.id.len())
            .saturating_add(edge.target.len()),
        is_cancelled,
    )?;
    Ok(path_step(edge))
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
    fn non_runtime_policy_evaluators_honor_work_budget_and_cancellation() -> Result<()> {
        let graph = snapshot(vec![
            edge("e1", "a", "b", "profile:production"),
            edge("e2", "b", "a", "profile:production"),
        ]);
        let cycle_rule = rule(PolicyRuleKind::Cycle);
        let admitted = admitted_edges_with_options(&graph, &cycle_rule, true, true)?;
        let nodes = graph
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<BTreeMap<_, _>>();
        let sources = vec![&graph.nodes[0]];
        let targets = vec![&graph.nodes[1]];
        let source_ids = BTreeSet::from(["a"]);
        let target_ids = BTreeSet::from(["b"]);

        let mut work = PolicyEvaluationWork::new(0);
        let exhausted = evaluate_cycles_bounded(
            &cycle_rule,
            &admitted,
            &source_ids,
            &target_ids,
            &nodes,
            &[],
            &mut work,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut threshold_rule = rule(PolicyRuleKind::DependencyDepth);
        threshold_rule.threshold = Some(PolicyThreshold { max: 0 });
        let mut work = PolicyEvaluationWork::new(0);
        let exhausted = evaluate_depth_bounded(
            &threshold_rule,
            &admitted,
            &sources,
            &targets,
            &nodes,
            &[],
            &mut work,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        threshold_rule.kind = PolicyRuleKind::FanOut;
        let mut work = PolicyEvaluationWork::new(0);
        let exhausted = evaluate_fan_out_bounded(
            &threshold_rule,
            &admitted,
            &sources,
            &target_ids,
            &nodes,
            &[],
            &mut work,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        threshold_rule.kind = PolicyRuleKind::FanIn;
        let mut work = PolicyEvaluationWork::new(0);
        let exhausted = evaluate_fan_in_bounded(
            &threshold_rule,
            &admitted,
            &source_ids,
            &targets,
            &nodes,
            &[],
            &mut work,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let cancelled = evaluate_fan_in_bounded(
            &threshold_rule,
            &admitted,
            &source_ids,
            &targets,
            &nodes,
            &[],
            &mut work,
            &mut || true,
        )
        .unwrap_err();
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
    fn public_api_diff_preflights_snapshot_clone_and_work() -> Result<()> {
        let mut public_rule = rule(PolicyRuleKind::PublicApiChange);
        public_rule.id = "bounded-public-api".to_owned();
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
        public_rule.condition = PolicyCondition::default();
        let policy = config(public_rule);

        let mut deep_value = json!(null);
        for _ in 0..20_000 {
            let mut object = serde_json::Map::new();
            object.insert("nested".to_owned(), deep_value);
            deep_value = Value::Object(object);
        }
        let mut from = snapshot(Vec::new());
        from.nodes = vec![NodeRecord {
            id: "public-api".to_owned(),
            kind: "symbol".to_owned(),
            locator: "symbol:public-api".to_owned(),
            display_name: "public-api".to_owned(),
            properties: deep_value,
        }];
        let mut to = snapshot(Vec::new());
        to.nodes = vec![semantic_node(
            "public-api",
            "symbol",
            "src/public.ts",
            json!({"signature":"v2"}),
        )];
        let deep_error = evaluate_policy_diff_cancellable(
            "before",
            &from,
            "after",
            &to,
            &policy,
            usize::MAX,
            || false,
        )
        .unwrap_err();
        assert!(deep_error.to_string().contains("nested deeper than"));
        // This intentionally leaks the manually assembled 20,000-level value:
        // serde_json::Value's public destructor is recursive, and this test is
        // specifically exercising the evaluator's preflight before it can be
        // dropped. Production snapshots are parser-bounded before ownership
        // reaches this path.
        std::mem::forget(from);

        let mut large_to = snapshot(Vec::new());
        large_to.nodes.push(semantic_node(
            "public-api",
            "symbol",
            "src/public.ts",
            json!({"signature":"v2"}),
        ));
        for index in 0..512 {
            large_to.nodes.push(semantic_node(
                &format!("unrelated-{index}"),
                "symbol",
                &format!("src/unrelated-{index}.ts"),
                json!({}),
            ));
        }
        let exhausted = evaluate_policy_diff_cancellable(
            "before",
            &snapshot(Vec::new()),
            "after",
            &large_to,
            &policy,
            128,
            || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut checks = 0;
        let cancelled = evaluate_policy_diff_cancellable(
            "before",
            &snapshot(Vec::new()),
            "after",
            &large_to,
            &policy,
            usize::MAX,
            || {
                checks += 1;
                checks > 24
            },
        )
        .unwrap_err();
        assert!(is_policy_evaluation_cancelled(&cancelled));
        assert_eq!(checks, 25);
        Ok(())
    }

    #[test]
    fn policy_preflights_deep_profile_values_before_context_materialization() -> Result<()> {
        let mut accepted_value = json!(null);
        for _ in 0..17 {
            let mut object = serde_json::Map::new();
            object.insert("nested".to_owned(), accepted_value);
            accepted_value = Value::Object(object);
        }
        let mut accepted_snapshot =
            snapshot(vec![edge("accepted:a-b", "a", "b", "profile:production")]);
        accepted_snapshot.profiles[0].environment = accepted_value;
        assert!(
            evaluate_policy_cancellable(
                "accepted",
                &accepted_snapshot,
                &config(rule(PolicyRuleKind::LayerBoundary)),
                usize::MAX,
                || false,
            )
            .is_ok()
        );

        let mut deep_value = json!(null);
        for _ in 0..20_000 {
            let mut object = serde_json::Map::new();
            object.insert("nested".to_owned(), deep_value);
            deep_value = Value::Object(object);
        }
        let mut snapshot = snapshot(vec![edge("edge:a-b", "a", "b", "profile:production")]);
        snapshot.profiles[0].environment = deep_value;
        let error = evaluate_policy_cancellable(
            "snapshot",
            &snapshot,
            &config(rule(PolicyRuleKind::LayerBoundary)),
            usize::MAX,
            || false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("nested deeper than"));
        // See the matching PublicApiChange preflight test above. Do not let
        // the fixture's recursive Value destructor turn a successful
        // evaluator rejection into a test-process stack overflow.
        std::mem::forget(snapshot);
        Ok(())
    }

    #[test]
    fn combined_condition_depth_boundary_is_explicit_and_bounded() -> Result<()> {
        fn nested_condition(depth: usize, suffix: &str) -> PolicyCondition {
            let mut condition = PolicyCondition::Eq {
                key: format!("leaf-{suffix}"),
                value: json!("value"),
            };
            for index in (0..depth).rev() {
                condition = if index % 2 == 0 {
                    PolicyCondition::Not {
                        condition: Box::new(condition),
                    }
                } else {
                    PolicyCondition::All {
                        conditions: vec![
                            condition,
                            PolicyCondition::Eq {
                                key: format!("extra-{suffix}-{index}"),
                                value: json!(index),
                            },
                        ],
                    }
                };
            }
            condition
        }

        let edge_a = edge("depth-a", "a", "b", "profile:production");
        let edge_b = edge("depth-b", "b", "c", "profile:production");
        let depth16 = [
            AdmittedEdge {
                edge: &edge_a,
                condition: nested_condition(16, "a"),
                evidence: Vec::new(),
                context: BTreeMap::new(),
            },
            AdmittedEdge {
                edge: &edge_b,
                condition: nested_condition(16, "b"),
                evidence: Vec::new(),
                context: BTreeMap::new(),
            },
        ];
        let depth16_refs = depth16.iter().collect::<Vec<_>>();
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let error =
            combined_condition_bounded(&depth16_refs, &mut work, &mut || false).unwrap_err();
        assert!(
            error
                .downcast_ref::<CombinedPolicyConditionDepthExceeded>()
                .is_some(),
            "depth overflow must fail at combined-condition validation"
        );

        let depth15 = [
            AdmittedEdge {
                edge: &edge_a,
                condition: nested_condition(15, "a"),
                evidence: Vec::new(),
                context: BTreeMap::new(),
            },
            AdmittedEdge {
                edge: &edge_b,
                condition: nested_condition(15, "b"),
                evidence: Vec::new(),
                context: BTreeMap::new(),
            },
        ];
        let depth15_refs = depth15.iter().collect::<Vec<_>>();
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        assert!(
            combined_condition_bounded(&depth15_refs, &mut work, &mut || false).is_ok(),
            "depth-15 edge conditions remain representable after path composition"
        );

        let flat = [
            AdmittedEdge {
                edge: &edge_a,
                condition: PolicyCondition::Eq {
                    key: "flat-a".to_owned(),
                    value: json!(true),
                },
                evidence: Vec::new(),
                context: BTreeMap::new(),
            },
            AdmittedEdge {
                edge: &edge_b,
                condition: PolicyCondition::Eq {
                    key: "flat-b".to_owned(),
                    value: json!(false),
                },
                evidence: Vec::new(),
                context: BTreeMap::new(),
            },
        ];
        let flat_refs = flat.iter().collect::<Vec<_>>();
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        assert!(combined_condition_bounded(&flat_refs, &mut work, &mut || false).is_ok());

        let exact_path = |value: &str| PolicySelector {
            match_kind: PolicyMatchKind::Exact,
            value: value.to_owned(),
            cardinality: PolicySelectorCardinality::One,
            ..selector("unused")
        };
        let mut depth16_edge_a = edge("actual-depth-a", "a", "b", "profile:production");
        depth16_edge_a.condition = serde_json::to_value(nested_condition(16, "actual-a"))?;
        let mut depth16_edge_b = edge("actual-depth-b", "b", "c", "profile:production");
        depth16_edge_b.condition = serde_json::to_value(nested_condition(16, "actual-b"))?;
        let depth16_graph = snapshot(vec![depth16_edge_a, depth16_edge_b]);
        let mut depth_rule = rule(PolicyRuleKind::DependencyDepth);
        depth_rule.source = exact_path("src/ui/a.ts");
        depth_rule.target = exact_path("src/data/c.ts");
        depth_rule.threshold = Some(PolicyThreshold { max: 1 });
        let error =
            evaluate_policy("snapshot:depth16", &depth16_graph, &config(depth_rule)).unwrap_err();
        assert!(
            error
                .downcast_ref::<CombinedPolicyConditionDepthExceeded>()
                .is_some(),
            "actual policy evaluation must reject the composed depth overflow"
        );

        let mut depth15_edge_a = edge("actual-depth-a", "a", "b", "profile:production");
        depth15_edge_a.condition = serde_json::to_value(nested_condition(15, "actual-a"))?;
        let mut depth15_edge_b = edge("actual-depth-b", "b", "c", "profile:production");
        depth15_edge_b.condition = serde_json::to_value(nested_condition(15, "actual-b"))?;
        let depth15_graph = snapshot(vec![depth15_edge_a, depth15_edge_b]);
        let mut depth_rule = rule(PolicyRuleKind::DependencyDepth);
        depth_rule.source = exact_path("src/ui/a.ts");
        depth_rule.target = exact_path("src/data/c.ts");
        depth_rule.threshold = Some(PolicyThreshold { max: 1 });
        let result = evaluate_policy("snapshot:depth15", &depth15_graph, &config(depth_rule))?;
        assert_eq!(result.violations.len(), 1);
        result.validate()?;
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
    fn bounded_cycle_detection_is_iterative_and_cancellable() -> Result<()> {
        const NODE_COUNT: usize = 512;
        let edges = (0..NODE_COUNT)
            .map(|index| {
                edge(
                    &format!("cycle-edge-{index}"),
                    &format!("cycle-node-{index}"),
                    &format!("cycle-node-{}", (index + 1) % NODE_COUNT),
                    "profile:production",
                )
            })
            .collect::<Vec<_>>();
        let mut graph = snapshot(edges);
        graph.nodes = (0..NODE_COUNT)
            .map(|index| {
                node(
                    &format!("cycle-node-{index}"),
                    &format!("src/cycle/{index}.ts"),
                )
            })
            .collect();
        let cycle_rule = rule(PolicyRuleKind::Cycle);
        let admitted = admitted_edges_with_options(&graph, &cycle_rule, true, true)?;
        let admitted = admitted.iter().collect::<Vec<_>>();
        let nodes = graph
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<BTreeMap<_, _>>();

        let mut work = PolicyEvaluationWork::new(128);
        let exhausted =
            cycle_rings_bounded(&nodes, &admitted, CycleLevel::File, &mut work, &mut || {
                false
            })
            .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut checks = 0;
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let cancelled =
            cycle_rings_bounded(&nodes, &admitted, CycleLevel::File, &mut work, &mut || {
                checks += 1;
                checks > 128
            })
            .unwrap_err();
        assert!(is_policy_evaluation_cancelled(&cancelled));
        assert_eq!(checks, 129);
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

    #[test]
    fn bounded_glob_preserves_path_semantics_and_charges_large_locators() -> Result<()> {
        for (pattern, value, expected) in [
            ("src/**/index.?s", "src/ui/deep/index.ts", true),
            ("src/**/index.?s", "src/index.ts", true),
            ("src/*/index.ts", "src/ui/deep/index.ts", false),
            ("src/*/index.ts", "src/ui/index.ts", true),
        ] {
            let mut work = PolicyEvaluationWork::new(10_000);
            assert_eq!(
                glob_matches_bounded(pattern, value, &mut work, &mut || false)?,
                expected
            );
        }

        let huge_locator = format!("file://{}", "a/".repeat(2_048));
        let node = NodeRecord {
            id: "huge-locator".to_owned(),
            kind: "file".to_owned(),
            locator: huge_locator.clone(),
            display_name: huge_locator,
            properties: json!({}),
        };
        let selector = PolicySelector {
            kind: PolicySelectorKind::File,
            field: PolicySelectorField::Locator,
            match_kind: PolicyMatchKind::Glob,
            value: "file://**".to_owned(),
            cardinality: PolicySelectorCardinality::Many,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        let mut work = PolicyEvaluationWork::new(32);
        let exhausted =
            selector_matches_node_bounded(&node, &selector, &mut work, &mut || false).unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut checks = 0;
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let cancelled = selector_matches_node_bounded(&node, &selector, &mut work, &mut || {
            checks += 1;
            checks > 32
        })
        .unwrap_err();
        assert!(is_policy_evaluation_cancelled(&cancelled));
        assert_eq!(checks, 33);

        let huge_literal = "segment/".repeat(2_048);
        for match_kind in [PolicyMatchKind::Exact, PolicyMatchKind::Prefix] {
            let mut work = PolicyEvaluationWork::new(32);
            let exhausted = pattern_matches_bounded(
                match_kind,
                &huge_literal,
                &huge_literal,
                &mut work,
                &mut || false,
            )
            .unwrap_err();
            assert!(is_policy_evaluation_resource_exhausted(&exhausted));
        }
        Ok(())
    }

    #[test]
    fn bounded_condition_evaluation_preserves_all_and_any_truth_tables() -> Result<()> {
        let context = BTreeMap::from([
            ("first".to_owned(), json!(true)),
            ("second".to_owned(), json!(false)),
        ]);
        let truth = PolicyCondition::Eq {
            key: "first".to_owned(),
            value: json!(true),
        };
        let falsehood = PolicyCondition::Eq {
            key: "second".to_owned(),
            value: json!(true),
        };
        for (condition, expected) in [
            (
                PolicyCondition::All {
                    conditions: vec![truth.clone(), truth.clone()],
                },
                Some(true),
            ),
            (
                PolicyCondition::Any {
                    conditions: vec![falsehood.clone(), falsehood.clone()],
                },
                Some(false),
            ),
            (
                PolicyCondition::All {
                    conditions: vec![truth.clone(), falsehood.clone()],
                },
                Some(false),
            ),
            (
                PolicyCondition::Any {
                    conditions: vec![truth.clone(), falsehood.clone()],
                },
                Some(true),
            ),
        ] {
            let mut work = PolicyEvaluationWork::new(1_000);
            assert_eq!(
                evaluate_condition_bounded_inner(
                    &condition,
                    &context,
                    false,
                    &mut work,
                    &mut || false,
                )?,
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn bounded_admitted_edge_conditions_are_iterative_and_cancellable() -> Result<()> {
        let mut deep_condition = json!({
            "op": "eq",
            "key": "mode",
            "value": "production"
        });
        for _ in 0..64 {
            let mut object = serde_json::Map::new();
            object.insert("op".to_owned(), Value::String("not".to_owned()));
            object.insert("condition".to_owned(), deep_condition);
            deep_condition = Value::Object(object);
        }
        let mut deep_graph = snapshot(vec![edge("deep-condition", "a", "b", "profile:production")]);
        deep_graph.edges[0].condition = deep_condition;
        let policy = rule(PolicyRuleKind::RuntimeBoundary);

        let mut work = PolicyEvaluationWork::new(16);
        let exhausted = admitted_edges_with_options_bounded(
            &deep_graph,
            &policy,
            false,
            true,
            &mut work,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut checks = 0;
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let cancelled = admitted_edges_with_options_bounded(
            &deep_graph,
            &policy,
            false,
            true,
            &mut work,
            &mut || {
                checks += 1;
                checks > 16
            },
        )
        .unwrap_err();
        assert!(is_policy_evaluation_cancelled(&cancelled));
        assert_eq!(checks, 17);

        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let exhausted = admitted_edges_with_options_bounded(
            &deep_graph,
            &policy,
            false,
            true,
            &mut work,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let many_children = (0..2_048)
            .map(|index| {
                json!({
                    "op":"eq",
                    "key": format!("condition-{index}"),
                    "value": true
                })
            })
            .collect::<Vec<_>>();
        let mut graph = snapshot(vec![edge("wide-condition", "a", "b", "profile:production")]);
        graph.edges[0].condition = json!({"op":"all","conditions":many_children});
        let mut work = PolicyEvaluationWork::new(64);
        let exhausted = admitted_edges_with_options_bounded(
            &graph,
            &policy,
            false,
            true,
            &mut work,
            &mut || false,
        )
        .unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let mut boundary_condition = json!({
            "op": "eq",
            "key": "mode",
            "value": "production"
        });
        for _ in 0..16 {
            boundary_condition = json!({"op":"not","condition":boundary_condition});
        }
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        assert!(
            parse_condition_bounded(&boundary_condition, "boundary", &mut work, &mut || false,)
                .is_ok()
        );
        boundary_condition = json!({"op":"not","condition":boundary_condition});
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        assert!(is_policy_evaluation_resource_exhausted(
            &parse_condition_bounded(&boundary_condition, "boundary", &mut work, &mut || false,)
                .unwrap_err()
        ));

        let protocol_compatible_conditions = [
            json!({"op":"in","key":"mode","values": []}),
            json!({"op":"in","key":"mode","values": ["production", "production"]}),
            json!({"op":"eq","key":"mode","value":""}),
            json!({"op":"eq","key":"feature flag/β","value":"\u{0000}"}),
        ];
        for value in protocol_compatible_conditions {
            let mut work = PolicyEvaluationWork::new(usize::MAX);
            assert!(
                parse_condition_bounded(&value, "protocol-v1", &mut work, &mut || false,).is_ok()
            );
        }

        let mut protocol_graph = snapshot(vec![edge(
            "empty-in-condition",
            "a",
            "b",
            "profile:production",
        )]);
        protocol_graph.edges[0].condition = json!({"op":"in","key":"mode","values": []});
        let mut work = PolicyEvaluationWork::new(usize::MAX);
        assert!(
            admitted_edges_with_options_bounded(
                &protocol_graph,
                &policy,
                false,
                false,
                &mut work,
                &mut || false,
            )?
            .is_empty()
        );

        let protocol_condition = json!({
            "op":"any",
            "conditions":[
                {"op":"in","key":"missing/value","values": []},
                {"op":"eq","key":"feature flag/β","value":"\u{0000}"},
                {"op":"eq","key":"blank/value","value":""}
            ]
        });
        let mut protocol_violation_graph = snapshot(vec![edge(
            "protocol-condition-violation",
            "a",
            "b",
            "profile:production",
        )]);
        protocol_violation_graph.profiles[0].environment = json!({
            "mode":"production",
            "feature flag/β":"\u{0000}",
            "blank/value":""
        });
        protocol_violation_graph.edges[0].condition = protocol_condition;
        let protocol_violation = evaluate_policy(
            "snapshot:protocol-condition",
            &protocol_violation_graph,
            &config(rule(PolicyRuleKind::LayerBoundary)),
        )?;
        assert_eq!(protocol_violation.violations.len(), 1);
        let projected_condition =
            serde_json::to_value(&protocol_violation.violations[0].condition)?;
        let projected_condition = projected_condition.to_string();
        assert!(projected_condition.contains("feature flag/β"));
        assert!(projected_condition.contains("blank/value"));
        assert!(projected_condition.contains("\"values\":[]"));

        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let empty_key = json!({"op":"eq","key":"","value": true});
        assert!(parse_condition_bounded(&empty_key, "invalid", &mut work, &mut || false,).is_err());

        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let oversized_key = json!({
            "op":"eq",
            "key":"k".repeat(129),
            "value": true
        });
        assert!(is_policy_evaluation_resource_exhausted(
            &parse_condition_bounded(&oversized_key, "resource-exhausted", &mut work, &mut || {
                false
            },)
            .unwrap_err()
        ));

        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let oversized_values = json!({
            "op":"in",
            "key":"mode",
            "values": vec![Value::Null; 129]
        });
        assert!(is_policy_evaluation_resource_exhausted(
            &parse_condition_bounded(
                &oversized_values,
                "resource-exhausted",
                &mut work,
                &mut || false,
            )
            .unwrap_err()
        ));

        let mut work = PolicyEvaluationWork::new(usize::MAX);
        let oversized_value = json!({
            "op":"eq",
            "key":"mode",
            "value":"v".repeat(1_025)
        });
        assert!(is_policy_evaluation_resource_exhausted(
            &parse_condition_bounded(
                &oversized_value,
                "resource-exhausted",
                &mut work,
                &mut || false,
            )
            .unwrap_err()
        ));

        // The logical depth limit is independent from the JSON wire depth:
        // every aggregate adds both an object and a `conditions` array. A
        // depth-16 aggregate chain with an `in` leaf is therefore valid and
        // must survive the snapshot preflight before the parser/evaluator.
        let mut valid_boundary_condition = json!({
            "op": "in",
            "key": "mode",
            "values": ["production"]
        });
        for _ in 0..16 {
            let mut object = serde_json::Map::new();
            object.insert("op".to_owned(), Value::String("all".to_owned()));
            object.insert(
                "conditions".to_owned(),
                Value::Array(vec![valid_boundary_condition]),
            );
            valid_boundary_condition = Value::Object(object);
        }
        let mut valid_graph = snapshot(vec![edge(
            "valid-boundary-condition",
            "a",
            "b",
            "profile:production",
        )]);
        valid_graph.edges[0].condition = valid_boundary_condition;
        let valid_result = evaluate_policy(
            "snapshot:valid",
            &valid_graph,
            &config(rule(PolicyRuleKind::LayerBoundary)),
        )?;
        assert_eq!(valid_result.violations.len(), 1);
        Ok(())
    }

    #[test]
    fn bounded_condition_canonicalization_matches_protocol_semantics() -> Result<()> {
        let conditions = [
            PolicyCondition::All {
                conditions: vec![
                    PolicyCondition::Eq {
                        key: "z".to_owned(),
                        value: json!("last"),
                    },
                    PolicyCondition::All {
                        conditions: vec![PolicyCondition::Eq {
                            key: "a".to_owned(),
                            value: json!("first"),
                        }],
                    },
                    PolicyCondition::All {
                        conditions: Vec::new(),
                    },
                ],
            },
            PolicyCondition::Any {
                conditions: vec![
                    PolicyCondition::Not {
                        condition: Box::new(PolicyCondition::Not {
                            condition: Box::new(PolicyCondition::In {
                                key: "mode".to_owned(),
                                values: vec![json!("production"), json!("production")],
                            }),
                        }),
                    },
                    PolicyCondition::Any {
                        conditions: vec![PolicyCondition::Defined {
                            key: "runtime".to_owned(),
                        }],
                    },
                ],
            },
        ];
        for condition in conditions {
            let expected = canonical_condition(&condition)?;
            let mut work = PolicyEvaluationWork::new(usize::MAX);
            let actual = canonical_condition_bounded(&condition, &mut work, &mut || false)?;
            assert_eq!(actual, expected);
        }

        let wide_in = PolicyCondition::In {
            key: "mode".to_owned(),
            values: (0..2_048)
                .map(|index| json!(format!("mode-{index}")))
                .collect(),
        };
        let mut work = PolicyEvaluationWork::new(128);
        let exhausted =
            canonical_condition_bounded(&wide_in, &mut work, &mut || false).unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));

        let large_atom = PolicyCondition::Eq {
            key: "k".repeat(2_048),
            value: json!("v".repeat(2_048)),
        };
        let mut work = PolicyEvaluationWork::new(128);
        let exhausted =
            condition_sort_key_bounded(&large_atom, &mut work, &mut || false).unwrap_err();
        assert!(is_policy_evaluation_resource_exhausted(&exhausted));
        Ok(())
    }
}
