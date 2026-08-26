use std::collections::{BTreeMap, BTreeSet, VecDeque};

use depgraph_store::GraphSnapshot;
use serde_json::json;

use crate::{
    query::{CycleLevel, cycles},
    service::DepgraphServiceError,
    service_graph::{CyclesRequest, cycles_bounded_with_cancellation},
};

use super::{
    BlockerKind, FindingBlocker, FindingIdentity, FindingKind, HealthFinding, Remediation,
    SurfaceRole, classify_surface, finish_finding,
};
use super::{HealthAnalysisError, budget::HealthAnalysisBudget};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditComparability {
    pub missing_base: bool,
    pub base_mismatch: bool,
    pub worktree_dirty: bool,
    pub profile_matrix_changed: bool,
    pub coverage_retreated: bool,
    pub policy_changed: bool,
    pub contract_changed: bool,
}

impl AuditComparability {
    #[must_use]
    pub fn blockers(&self) -> Vec<FindingBlocker> {
        let mut blockers = Vec::new();
        let mut push = |present: bool, kind: BlockerKind, detail: &str| {
            if present {
                blockers.push(FindingBlocker {
                    kind,
                    detail: detail.to_owned(),
                });
            }
        };
        push(
            self.missing_base,
            BlockerKind::MissingBaseSnapshot,
            "no completed snapshot matches the resolved base commit",
        );
        push(
            self.base_mismatch,
            BlockerKind::BaseSnapshotMismatch,
            "explicit base snapshot source_revision does not match the base OID",
        );
        push(
            self.worktree_dirty,
            BlockerKind::WorktreeDirty,
            "worktree has edits that are not in the changed-set HEAD",
        );
        push(
            self.profile_matrix_changed,
            BlockerKind::IncomparableProfileMatrix,
            "before/after profile matrix identities differ",
        );
        push(
            self.coverage_retreated,
            BlockerKind::IncomparableCoverage,
            "after snapshot completeness retreated relative to before",
        );
        push(
            self.policy_changed,
            BlockerKind::IncomparablePolicy,
            "policy digest differs between the audit inputs",
        );
        push(
            self.contract_changed,
            BlockerKind::IncomparableContract,
            "analyzer or finding contract versions differ",
        );
        blockers
    }

    #[must_use]
    pub fn new_checks_are_indeterminate(&self) -> bool {
        self.missing_base
            || self.base_mismatch
            || self.profile_matrix_changed
            || self.coverage_retreated
            || self.policy_changed
            || self.contract_changed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthAuditInputIdentity {
    pub after_snapshot_id: String,
    pub before_snapshot_id: Option<String>,
    pub changed_oid: String,
}

#[must_use]
pub fn canonical_cycle_rotation(node_ids: &[String]) -> Vec<String> {
    let cycle = if node_ids.len() > 1 && node_ids.first() == node_ids.last() {
        &node_ids[..node_ids.len() - 1]
    } else {
        node_ids
    };
    if cycle.is_empty() {
        return Vec::new();
    }
    let mut best = cycle.to_vec();
    for start in 0..cycle.len() {
        let mut candidate = cycle[start..].to_vec();
        candidate.extend(cycle[..start].iter().cloned());
        if candidate < best {
            best = candidate;
        }
    }
    best
}

#[must_use]
pub fn analyze_changed_code(
    after: &GraphSnapshot,
    before: Option<&GraphSnapshot>,
    changed_node_ids: &[String],
    comparability: &AuditComparability,
) -> Vec<HealthFinding> {
    analyze_changed_code_cancellable(
        after,
        before,
        changed_node_ids,
        comparability,
        usize::MAX,
        usize::MAX,
        || false,
    )
    .expect("unbounded, non-cancellable changed-code analysis cannot fail")
}

pub fn analyze_changed_code_cancellable(
    after: &GraphSnapshot,
    before: Option<&GraphSnapshot>,
    changed_node_ids: &[String],
    comparability: &AuditComparability,
    maximum_findings: usize,
    maximum_work: usize,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<Vec<HealthFinding>, HealthAnalysisError> {
    let mut budget = HealthAnalysisBudget::new(maximum_work);
    let shared_blockers = comparability.blockers();
    let new_checks_indeterminate = comparability.new_checks_are_indeterminate();
    let mut findings = Vec::new();
    if let Some(before) = before {
        let before_cycles = cycle_identities(before, maximum_work, &mut budget, &mut is_cancelled)?;
        let after_cycles = cycle_identities(after, maximum_work, &mut budget, &mut is_cancelled)?;
        for rotation in after_cycles.difference(&before_cycles) {
            budget.step(&mut is_cancelled)?;
            push_finding(
                &mut findings,
                maximum_findings,
                audit_finding(
                    FindingKind::NewCycle,
                    rotation.join("->"),
                    rotation.clone(),
                    "cycle is present after the change and absent before",
                    &shared_blockers,
                    new_checks_indeterminate,
                ),
            )?;
        }
        let before_boundaries = boundary_identities(before, &mut budget, &mut is_cancelled)?;
        let after_boundaries = boundary_identities(after, &mut budget, &mut is_cancelled)?;
        for identity in after_boundaries.difference(&before_boundaries) {
            budget.step(&mut is_cancelled)?;
            push_finding(
                &mut findings,
                maximum_findings,
                audit_finding(
                    FindingKind::NewBoundaryViolation,
                    identity.clone(),
                    vec![identity.clone()],
                    "boundary violation is present after the change and absent before",
                    &shared_blockers,
                    new_checks_indeterminate,
                ),
            )?;
        }
        for change in public_api_changes(before, after, &mut budget, &mut is_cancelled)? {
            budget.step(&mut is_cancelled)?;
            push_finding(
                &mut findings,
                maximum_findings,
                audit_finding(
                    FindingKind::PublicApiChange,
                    change.0.clone(),
                    vec![change.0],
                    change.1,
                    &shared_blockers,
                    new_checks_indeterminate,
                ),
            )?;
        }
    } else {
        for kind in [
            FindingKind::NewCycle,
            FindingKind::NewBoundaryViolation,
            FindingKind::PublicApiChange,
        ] {
            budget.step(&mut is_cancelled)?;
            push_finding(
                &mut findings,
                maximum_findings,
                audit_finding(
                    kind,
                    format!("degraded:{}", kind.as_str()),
                    vec![kind.as_str().to_owned()],
                    "new-only comparison degraded because a comparable base snapshot is unavailable",
                    &shared_blockers,
                    true,
                ),
            )?;
        }
    }
    let mut impacted = reverse_impact(after, changed_node_ids, &mut budget, &mut is_cancelled)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if let Some(before) = before.filter(|_| !comparability.base_mismatch) {
        for node_id in reverse_impact(before, changed_node_ids, &mut budget, &mut is_cancelled)? {
            budget.step(&mut is_cancelled)?;
            impacted.insert(node_id);
        }
    }
    let mut changed = BTreeSet::new();
    for node_id in changed_node_ids {
        budget.step(&mut is_cancelled)?;
        changed.insert(node_id);
    }
    let changed_count = changed.len();
    if changed_count > 0 && impacted.len() > changed_count {
        let impacted_count = impacted.len();
        let impacted = impacted.into_iter().collect::<Vec<_>>();
        let subject = changed_node_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "changed-set".to_owned());
        let blast_blockers = shared_blockers
            .iter()
            .filter(|blocker| {
                matches!(
                    blocker.kind,
                    BlockerKind::BaseSnapshotMismatch
                        | BlockerKind::WorktreeDirty
                        | BlockerKind::IncomparableProfileMatrix
                        | BlockerKind::IncomparableCoverage
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        push_finding(
            &mut findings,
            maximum_findings,
            audit_finding(
                FindingKind::WideBlastRadius,
                subject,
                impacted,
                format!(
                    "reverse impact reaches {} nodes from {changed_count} changed nodes",
                    impacted_count
                ),
                &blast_blockers,
                !blast_blockers.is_empty(),
            ),
        )?;
    }
    budget.step(&mut is_cancelled)?;
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(findings)
}

fn cycle_identities(
    snapshot: &GraphSnapshot,
    maximum_work: usize,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeSet<Vec<String>>, HealthAnalysisError> {
    let mut identities = BTreeSet::new();
    for level in [CycleLevel::Package, CycleLevel::File, CycleLevel::Symbol] {
        budget.step(is_cancelled)?;
        let detected = if maximum_work == usize::MAX {
            cycles(snapshot, level)
        } else {
            let maximum_traversal = maximum_work.min(crate::query::MAX_INTERACTIVE_QUERY_TRAVERSAL);
            let request = CyclesRequest::try_new(level, maximum_traversal)
                .map_err(|_| HealthAnalysisError::ResourceExhausted)?;
            let mut callback_error = None;
            let result = cycles_bounded_with_cancellation(snapshot, &request, &mut || {
                if callback_error.is_some() {
                    return true;
                }
                match budget.step(is_cancelled) {
                    Ok(()) => false,
                    Err(error) => {
                        callback_error = Some(error);
                        true
                    }
                }
            });
            if let Some(error) = callback_error {
                return Err(error);
            }
            result.map_err(map_cycle_error)?
        };
        for cycle in detected {
            budget.step(is_cancelled)?;
            identities.insert(canonical_cycle_rotation_bounded(
                &cycle.node_ids,
                budget,
                is_cancelled,
            )?);
        }
    }
    Ok(identities)
}

fn map_cycle_error(error: DepgraphServiceError) -> HealthAnalysisError {
    match error {
        DepgraphServiceError::Cancelled => HealthAnalysisError::Cancelled,
        DepgraphServiceError::ResourceExhausted => HealthAnalysisError::ResourceExhausted,
        _ => HealthAnalysisError::Integrity,
    }
}

fn canonical_cycle_rotation_bounded(
    node_ids: &[String],
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<String>, HealthAnalysisError> {
    let cycle = if node_ids.len() > 1 && node_ids.first() == node_ids.last() {
        &node_ids[..node_ids.len() - 1]
    } else {
        node_ids
    };
    if cycle.is_empty() {
        return Ok(Vec::new());
    }
    let mut best = Vec::with_capacity(cycle.len());
    for node_id in cycle {
        budget.step(is_cancelled)?;
        best.push(node_id.clone());
    }
    for start in 1..cycle.len() {
        budget.step(is_cancelled)?;
        let mut candidate = Vec::with_capacity(cycle.len());
        for offset in 0..cycle.len() {
            budget.step(is_cancelled)?;
            candidate.push(cycle[(start + offset) % cycle.len()].clone());
        }
        if candidate < best {
            best = candidate;
        }
    }
    Ok(best)
}

fn boundary_identities(
    snapshot: &GraphSnapshot,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeSet<String>, HealthAnalysisError> {
    let mut identities = BTreeSet::new();
    for diagnostic in &snapshot.diagnostics {
        budget.step(is_cancelled)?;
        if diagnostic.code.contains("boundary") || diagnostic.code.contains("policy") {
            identities.insert(diagnostic.id.clone());
        }
    }
    Ok(identities)
}

fn public_api_changes(
    before: &GraphSnapshot,
    after: &GraphSnapshot,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<(String, String)>, HealthAnalysisError> {
    let before_public = public_subjects(before, budget, is_cancelled)?;
    let after_public = public_subjects(after, budget, is_cancelled)?;
    let mut changes = Vec::new();
    for (id, after_sig) in &after_public {
        budget.step(is_cancelled)?;
        match before_public.get(id) {
            None => changes.push((id.clone(), "public surface was added".to_owned())),
            Some(before_sig) if before_sig != after_sig => {
                changes.push((id.clone(), "public surface signature changed".to_owned()));
            }
            Some(_) => {}
        }
    }
    for id in before_public.keys() {
        budget.step(is_cancelled)?;
        if !after_public.contains_key(id) {
            changes.push((id.clone(), "public surface was removed".to_owned()));
        }
    }
    budget.step(is_cancelled)?;
    changes.sort();
    Ok(changes)
}

fn public_subjects(
    snapshot: &GraphSnapshot,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<String, String>, HealthAnalysisError> {
    let mut subjects = BTreeMap::new();
    for node in &snapshot.nodes {
        budget.step(is_cancelled)?;
        if matches!(
            classify_surface(node).role,
            SurfaceRole::PublicSurface | SurfaceRole::EntryPoint
        ) {
            subjects.insert(
                node.id.clone(),
                depgraph_protocol::canonical_json(&json!({
                    "canonical_identity": node.properties.get("canonical_identity"),
                    "display_name": &node.display_name,
                    "exported": node.properties.get("exported"),
                    "kind": &node.kind,
                    "locator": &node.locator,
                    "public": node.properties.get("public"),
                    "signature": node.properties.get("signature"),
                    "symbol_kind": node.properties.get("symbol_kind"),
                    "type_kind": node.properties.get("type_kind"),
                    "visibility": node.properties.get("visibility"),
                })),
            );
        }
    }
    Ok(subjects)
}

fn reverse_impact(
    snapshot: &GraphSnapshot,
    changed: &[String],
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<String>, HealthAnalysisError> {
    let mut incoming = BTreeMap::<&str, Vec<&str>>::new();
    for edge in &snapshot.edges {
        budget.step(is_cancelled)?;
        incoming
            .entry(edge.target.as_str())
            .or_default()
            .push(edge.source.as_str());
    }
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    for id in changed {
        budget.step(is_cancelled)?;
        if seen.insert(id.clone()) {
            queue.push_back(id.clone());
        }
    }
    while let Some(current) = queue.pop_front() {
        budget.step(is_cancelled)?;
        if let Some(parents) = incoming.get(current.as_str()) {
            for parent in parents {
                budget.step(is_cancelled)?;
                if seen.insert((*parent).to_owned()) {
                    queue.push_back((*parent).to_owned());
                }
            }
        }
    }
    Ok(seen.into_iter().collect())
}

fn push_finding(
    findings: &mut Vec<HealthFinding>,
    maximum_findings: usize,
    finding: HealthFinding,
) -> Result<(), HealthAnalysisError> {
    if findings.len() >= maximum_findings {
        return Err(HealthAnalysisError::ResourceExhausted);
    }
    findings.push(finding);
    Ok(())
}

fn audit_finding(
    kind: FindingKind,
    subject_id: String,
    witness: Vec<String>,
    reason: impl Into<String>,
    shared_blockers: &[FindingBlocker],
    force_indeterminate: bool,
) -> HealthFinding {
    let mut blockers = shared_blockers.to_vec();
    if force_indeterminate
        && !blockers
            .iter()
            .any(|blocker| blocker.kind.blocks_confirmed())
    {
        blockers.push(FindingBlocker {
            kind: BlockerKind::IncompleteCoverage,
            detail: "audit comparison is not confirmed".to_owned(),
        });
    }
    finish_finding(
        FindingIdentity {
            kind,
            subject_id: subject_id.clone(),
            profile_scope: None,
            witness_key: json!({ "witness": witness }),
        },
        kind.as_str(),
        None,
        reason.into(),
        blockers,
        Vec::new(),
        vec![Remediation {
            kind: "use-health-audit".to_owned(),
            detail: "inspect the snapshot pair, changed OID, and blockers before merging"
                .to_owned(),
        }],
        Vec::new(),
        false,
        !force_indeterminate && shared_blockers.is_empty(),
    )
}

#[cfg(test)]
mod tests {
    use depgraph_store::{CoverageRecord, EdgeRecord, NodeRecord, ProfileMatrixRecord, ScanRecord};
    use serde_json::json;

    use super::*;

    fn empty_snapshot() -> GraphSnapshot {
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan:audit".to_owned(),
                root: "/tmp/fixture".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "2026-01-01T00:00:00Z".to_owned(),
                completed_at: Some("2026-01-01T00:00:01Z".to_owned()),
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: Some("a".repeat(40)),
            },
            profiles: Vec::new(),
            nodes: Vec::new(),
            sites: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: ProfileMatrixRecord::default(),
        }
    }

    #[test]
    fn issue_423_canonical_cycle_rotation_is_stable() {
        assert_eq!(
            canonical_cycle_rotation(&["b".to_owned(), "c".to_owned(), "a".to_owned()]),
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
        assert_eq!(
            canonical_cycle_rotation(&["a".to_owned(), "b".to_owned(), "c".to_owned()]),
            canonical_cycle_rotation(&["c".to_owned(), "a".to_owned(), "b".to_owned()])
        );
        assert_eq!(
            canonical_cycle_rotation(&["a".to_owned(), "b".to_owned(), "a".to_owned()]),
            canonical_cycle_rotation(&["b".to_owned(), "a".to_owned(), "b".to_owned()])
        );
    }

    #[test]
    fn issue_423_changed_code_analysis_is_bounded_and_cancellable() {
        let snapshot = empty_snapshot();
        assert_eq!(
            analyze_changed_code_cancellable(
                &snapshot,
                None,
                &[],
                &AuditComparability::default(),
                usize::MAX,
                0,
                || false,
            ),
            Err(HealthAnalysisError::ResourceExhausted)
        );
        assert_eq!(
            analyze_changed_code_cancellable(
                &snapshot,
                None,
                &[],
                &AuditComparability::default(),
                usize::MAX,
                usize::MAX,
                || true,
            ),
            Err(HealthAnalysisError::Cancelled)
        );
        assert_eq!(
            analyze_changed_code_cancellable(
                &snapshot,
                None,
                &[],
                &AuditComparability::default(),
                0,
                usize::MAX,
                || false,
            ),
            Err(HealthAnalysisError::ResourceExhausted)
        );
    }

    #[test]
    fn issue_423_deleted_subject_uses_before_snapshot_for_blast_radius() {
        let mut before = empty_snapshot();
        before.nodes = vec![
            NodeRecord {
                id: "file:caller".to_owned(),
                kind: "file".to_owned(),
                locator: "repo://src/caller.rs".to_owned(),
                display_name: "caller.rs".to_owned(),
                properties: json!({"path": "src/caller.rs", "language": "rust"}),
            },
            NodeRecord {
                id: "file:deleted".to_owned(),
                kind: "file".to_owned(),
                locator: "repo://src/deleted.rs".to_owned(),
                display_name: "deleted.rs".to_owned(),
                properties: json!({"path": "src/deleted.rs", "language": "rust"}),
            },
        ];
        before.edges.push(EdgeRecord {
            id: "edge:caller-deleted".to_owned(),
            site_id: None,
            source: "file:caller".to_owned(),
            target: "file:deleted".to_owned(),
            kind: "imports".to_owned(),
            phase: "semantic".to_owned(),
            environment: "host".to_owned(),
            profile_id: "rust:lib".to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({}),
            generated: false,
        });
        let after = empty_snapshot();
        let findings = analyze_changed_code(
            &after,
            Some(&before),
            &["file:deleted".to_owned()],
            &AuditComparability::default(),
        );
        let blast = findings
            .iter()
            .find(|finding| finding.kind == FindingKind::WideBlastRadius)
            .expect("blast radius from deleted subject");
        assert!(blast.reason.contains("2 nodes from 1 changed nodes"));
    }
}
