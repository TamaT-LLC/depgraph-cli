use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use anyhow::{Context, Result, bail};
use depgraph_protocol::EvidenceKind;
use depgraph_store::{EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, ProfileRecord};
use serde::Serialize;
use serde_json::Value;

use crate::{
    policy::{
        AppliedPolicySuppression, PolicyCondition, PolicyConfig, PolicyEntity,
        PolicyEvidenceRequirement, PolicyEvidenceSpan, PolicyMatchKind, PolicyPathStep,
        PolicyPattern, PolicyProfileFilter, PolicyResult, PolicyRule, PolicyRuleKind,
        PolicySelector, PolicySelectorCardinality, PolicySelectorField, PolicySelectorKind,
        PolicySuppression, PolicyViolation,
    },
    query::{CycleLevel, cycles},
};

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
    config.validate()?;
    let nodes: BTreeMap<_, _> = snapshot
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let suppressions = resolve_suppressions(snapshot, config)?;
    let mut violations = BTreeMap::new();

    for rule in &config.rules {
        let sources = resolve_selector(
            snapshot,
            &rule.source,
            &format!("rule {:?} source", rule.id),
        )?;
        let targets = resolve_selector(
            snapshot,
            &rule.target,
            &format!("rule {:?} target", rule.id),
        )?;
        let source_ids: BTreeSet<_> = sources.iter().map(|node| node.id.as_str()).collect();
        let target_ids: BTreeSet<_> = targets.iter().map(|node| node.id.as_str()).collect();
        let admitted = admitted_edges(snapshot, rule)?;

        let evaluated = match rule.kind {
            PolicyRuleKind::LayerBoundary | PolicyRuleKind::ForbiddenDependency => evaluate_direct(
                rule,
                &admitted,
                &source_ids,
                &target_ids,
                &nodes,
                &suppressions,
            )?,
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
            PolicyRuleKind::PublicApiChange | PolicyRuleKind::RuntimeBoundary => bail!(
                "policy rule {:?} uses {:?}, which is not supported by the static architecture evaluator",
                rule.id,
                rule.kind
            ),
        };
        for violation in evaluated {
            violations.entry(violation.id.clone()).or_insert(violation);
        }
    }

    let result = PolicyResult::new(snapshot_id, violations.into_values().collect());
    result.validate()?;
    Ok(result)
}

#[derive(Debug)]
struct AdmittedEdge<'a> {
    edge: &'a EdgeRecord,
    condition: PolicyCondition,
    evidence: Vec<PolicyEvidenceSpan>,
    context: BTreeMap<String, Value>,
}

#[derive(Debug)]
struct ResolvedSuppression<'a> {
    suppression: &'a PolicySuppression,
    source_ids: Option<BTreeSet<String>>,
    target_ids: Option<BTreeSet<String>>,
}

fn resolve_suppressions<'a>(
    snapshot: &GraphSnapshot,
    config: &'a PolicyConfig,
) -> Result<Vec<ResolvedSuppression<'a>>> {
    let mut resolved = Vec::with_capacity(config.suppressions.len());
    for suppression in &config.suppressions {
        let source_ids = suppression
            .scope
            .source
            .as_ref()
            .map(|selector| {
                resolve_selector(
                    snapshot,
                    selector,
                    &format!("suppression {:?} source", suppression.id),
                )
                .map(|nodes| nodes.into_iter().map(|node| node.id.clone()).collect())
            })
            .transpose()?;
        let target_ids = suppression
            .scope
            .target
            .as_ref()
            .map(|selector| {
                resolve_selector(
                    snapshot,
                    selector,
                    &format!("suppression {:?} target", suppression.id),
                )
                .map(|nodes| nodes.into_iter().map(|node| node.id.clone()).collect())
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

fn admitted_edges<'a>(
    snapshot: &'a GraphSnapshot,
    rule: &PolicyRule,
) -> Result<Vec<AdmittedEdge<'a>>> {
    let profiles: BTreeMap<_, _> = snapshot
        .profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect();
    let evidence: BTreeMap<_, Vec<_>> = {
        let mut by_owner: BTreeMap<(&str, &str), Vec<&EvidenceRecord>> = BTreeMap::new();
        for item in &snapshot.evidence {
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
        if !profile_matches(&rule.profiles, &edge.profile_id)
            || !allowed_precisions.contains(edge.precision.as_str())
            || !allowed_statuses.contains(edge.resolution_status.as_str())
        {
            continue;
        }

        let condition: PolicyCondition = serde_json::from_value(edge.condition.clone())
            .with_context(|| format!("edge {:?} has an invalid policy condition", edge.id))?;
        let mut context = edge_context(edge, profiles.get(edge.profile_id.as_str()).copied());
        if evaluate_edge_condition(&condition, &context) == Some(false) {
            continue;
        }
        add_condition_facts(&condition, &mut context);
        if evaluate_condition(&rule.condition, &context) != Some(true) {
            continue;
        }

        let spans = select_evidence(edge, &rule.evidence, &evidence)?;
        if spans.len() < usize::try_from(rule.evidence.minimum_spans)? {
            continue;
        }
        admitted.push(AdmittedEdge {
            edge,
            condition: canonical_condition(&condition)?,
            evidence: spans,
            context,
        });
    }
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

fn evaluate_direct(
    rule: &PolicyRule,
    admitted: &[AdmittedEdge<'_>],
    source_ids: &BTreeSet<&str>,
    target_ids: &BTreeSet<&str>,
    nodes: &BTreeMap<&str, &NodeRecord>,
    suppressions: &[ResolvedSuppression<'_>],
) -> Result<Vec<PolicyViolation>> {
    admitted
        .iter()
        .filter(|item| {
            source_ids.contains(item.edge.source.as_str())
                && target_ids.contains(item.edge.target.as_str())
        })
        .map(|item| {
            let path = vec![path_step(item.edge)];
            make_violation(
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
            )
        })
        .collect()
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
    let cycle_nodes: BTreeSet<_> = source_ids.intersection(target_ids).copied().collect();
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
            let Some(start) = ring.iter().min() else {
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
    let mut adjacency: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for edge in edges {
        adjacency
            .entry(edge.edge.source.as_str())
            .or_default()
            .push(*edge);
    }
    for outgoing in adjacency.values_mut() {
        outgoing.sort_by(|left, right| {
            (&left.edge.target, &left.edge.id).cmp(&(&right.edge.target, &right.edge.id))
        });
    }
    adjacency
}

fn reconstruct_path<'a>(
    source: &str,
    target: &str,
    predecessor: &HashMap<String, &'a AdmittedEdge<'a>>,
) -> Result<Vec<&'a AdmittedEdge<'a>>> {
    let mut current = target;
    let mut reversed = Vec::new();
    while current != source {
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
    let source_node = nodes
        .get(source_id)
        .copied()
        .with_context(|| format!("policy source node {source_id:?} is missing"))?;
    let target_node = nodes
        .get(target_id)
        .copied()
        .with_context(|| format!("policy target node {target_id:?} is missing"))?;
    let mut evidence: Vec<_> = path_edges
        .iter()
        .flat_map(|item| item.evidence.iter().cloned())
        .collect();
    canonicalize_evidence(&mut evidence);
    let condition = combined_condition(&path_edges)?;
    let context = path_edges
        .first()
        .map_or_else(BTreeMap::new, |item| item.context.clone());
    let suppression = applied_suppression(
        suppressions,
        &rule.id,
        source_id,
        target_id,
        profile_id,
        &context,
    );
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
                && profile_id.is_some_and(|profile| profile_matches(&scope.profiles, profile))
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

fn resolve_selector<'a>(
    snapshot: &'a GraphSnapshot,
    selector: &PolicySelector,
    description: &str,
) -> Result<Vec<&'a NodeRecord>> {
    let mut matches: Vec<_> = snapshot
        .nodes
        .iter()
        .filter(|node| selector_matches_node(node, selector))
        .collect();
    matches.sort_by(|left, right| left.id.cmp(&right.id));
    if selector.cardinality == PolicySelectorCardinality::One && matches.len() != 1 {
        bail!(
            "policy selector {description} must resolve to exactly one node, but matched {}",
            matches.len()
        );
    }
    Ok(matches)
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

fn node_kind_matches(node: &NodeRecord, kind: PolicySelectorKind) -> bool {
    match kind {
        PolicySelectorKind::Package => node.kind == "package_instance" || node.kind == "package",
        PolicySelectorKind::File => node.kind == "file",
        PolicySelectorKind::Symbol => node.kind == "symbol",
        PolicySelectorKind::Type => node.kind == "type",
        PolicySelectorKind::Route => node.kind == "route",
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

fn profile_matches(filter: &PolicyProfileFilter, profile_id: &str) -> bool {
    (filter.include.is_empty() || patterns_match(&filter.include, profile_id))
        && !patterns_match(&filter.exclude, profile_id)
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

fn select_evidence(
    edge: &EdgeRecord,
    requirement: &PolicyEvidenceRequirement,
    evidence: &BTreeMap<(&str, &str), Vec<&EvidenceRecord>>,
) -> Result<Vec<PolicyEvidenceSpan>> {
    let mut records = evidence
        .get(&("edge", edge.id.as_str()))
        .cloned()
        .unwrap_or_default();
    if records.is_empty()
        && let Some(site_id) = edge.site_id.as_deref()
    {
        records = evidence
            .get(&("site", site_id))
            .cloned()
            .unwrap_or_default();
    }
    records.sort_by(|left, right| {
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
    for record in records {
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
    canonicalize_evidence(&mut spans);
    Ok(spans)
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
