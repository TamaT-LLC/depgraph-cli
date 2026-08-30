use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use depgraph_protocol::stable_id_from_value;
use depgraph_store::GraphSnapshot;
use sha2::{Digest as _, Sha256};

use crate::{
    CancellationToken,
    bounded_query::{QueryFailureClass, read_bounded_repository_file},
    health::{
        AuditAnalysisOptions, AuditComparability, CollectionIdentity, Confidence, FindingKind,
        HealthAnalysisError, HealthFinding, HealthFindingDetail, HotspotAnalysisError,
        HotspotLayerAvailability, HotspotWeights, ManifestIdentity, Severity,
        analyze_changed_code_with_boundary_ids_cancellable, analyze_dependencies_cancellable,
        analyze_unused_cancellable, collection_digest, contract::collection_digest_with_policy,
        score_hotspots_cancellable,
    },
    impact::{
        GitChangedSet, is_resource_exhausted, map_changed_set_cancellable,
        read_git_changed_set_cancellable, read_git_churn_cancellable,
    },
    service::{
        DepgraphService, DepgraphServiceError, DepgraphServiceResult, RepositoryRelativePath,
        ResolvedSnapshotId, SnapshotLocator, SnapshotReadRequest,
    },
    service_artifacts::preflight_graph_work,
    service_graph::load_pinned_snapshot,
    service_limits::{
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS, MAX_HEALTH_BLOCKERS_PER_FINDING,
        MAX_HEALTH_CHURN_COMMITS, MAX_HEALTH_EVIDENCE_PER_FINDING, MAX_HEALTH_FILTER_ITEMS,
        MAX_HEALTH_FINDINGS, MAX_HEALTH_MANIFEST_BYTES, MAX_HEALTH_MANIFESTS,
        MAX_HEALTH_REMEDIATIONS_PER_FINDING, MAX_HEALTH_SUPPRESSIONS_PER_FINDING,
        MAX_HEALTH_TOTAL_MANIFEST_BYTES,
    },
};

use crate::{
    policy::PolicyConfig,
    policy_engine::{
        evaluate_boundary_violation_ids_cancellable, is_policy_evaluation_cancelled,
        is_policy_evaluation_resource_exhausted,
    },
};

const MAX_GIT_REF_BYTES: usize = 256;

#[derive(Clone, Debug)]
pub struct HealthSummaryRequest {
    kinds: Option<Vec<FindingKind>>,
}

impl HealthSummaryRequest {
    pub fn try_new(mut kinds: Option<Vec<FindingKind>>) -> DepgraphServiceResult<Self> {
        if let Some(kinds) = &mut kinds {
            if kinds.is_empty()
                || kinds.len() > MAX_HEALTH_FILTER_ITEMS
                || kinds.iter().any(|kind| !kind.is_snapshot_scoped())
            {
                return Err(DepgraphServiceError::InvalidInput);
            }
            kinds.sort_unstable();
            kinds.dedup();
        }
        Ok(Self { kinds })
    }

    #[must_use]
    pub fn kinds(&self) -> Option<&[FindingKind]> {
        self.kinds.as_deref()
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct HealthCoverageOverview {
    pub completeness: Vec<String>,
    pub files_skipped: u64,
    pub unresolved: u64,
    pub candidates: u64,
}

#[derive(Clone, Debug)]
pub struct HealthSummaryResult {
    snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    collection_digest: String,
    manifest_digest: Option<String>,
    counts_by_kind: BTreeMap<String, u64>,
    counts_by_confidence: BTreeMap<String, u64>,
    coverage: HealthCoverageOverview,
}

impl HealthSummaryResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub fn collection_digest(&self) -> &str {
        &self.collection_digest
    }

    #[must_use]
    pub fn manifest_digest(&self) -> Option<&str> {
        self.manifest_digest.as_deref()
    }

    #[must_use]
    pub const fn counts_by_kind(&self) -> &BTreeMap<String, u64> {
        &self.counts_by_kind
    }

    #[must_use]
    pub const fn counts_by_confidence(&self) -> &BTreeMap<String, u64> {
        &self.counts_by_confidence
    }

    #[must_use]
    pub const fn coverage(&self) -> &HealthCoverageOverview {
        &self.coverage
    }
}

#[derive(Clone, Debug)]
pub struct HealthFindingsRequest {
    kinds: Vec<FindingKind>,
    severities: Vec<Severity>,
    confidences: Vec<Confidence>,
    limit: usize,
}

impl HealthFindingsRequest {
    pub fn try_new(
        mut kinds: Vec<FindingKind>,
        mut severities: Vec<Severity>,
        mut confidences: Vec<Confidence>,
        limit: usize,
    ) -> DepgraphServiceResult<Self> {
        if kinds.len() > MAX_HEALTH_FILTER_ITEMS
            || severities.len() > MAX_HEALTH_FILTER_ITEMS
            || confidences.len() > MAX_HEALTH_FILTER_ITEMS
            || kinds.iter().any(|kind| !kind.is_snapshot_scoped())
            || !(1..=MAX_HEALTH_FINDINGS).contains(&limit)
        {
            return Err(DepgraphServiceError::InvalidInput);
        }
        kinds.sort_unstable();
        kinds.dedup();
        severities.sort_unstable();
        severities.dedup();
        confidences.sort_unstable();
        confidences.dedup();
        Ok(Self {
            kinds,
            severities,
            confidences,
            limit,
        })
    }

    #[must_use]
    pub fn kinds(&self) -> &[FindingKind] {
        &self.kinds
    }

    #[must_use]
    pub fn severities(&self) -> &[Severity] {
        &self.severities
    }

    #[must_use]
    pub fn confidences(&self) -> &[Confidence] {
        &self.confidences
    }

    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

#[derive(Clone, Debug)]
pub struct HealthFindingsResult {
    snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    collection_digest: String,
    manifest_digest: Option<String>,
    findings: Vec<HealthFinding>,
}

impl HealthFindingsResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub fn collection_digest(&self) -> &str {
        &self.collection_digest
    }

    #[must_use]
    pub fn manifest_digest(&self) -> Option<&str> {
        self.manifest_digest.as_deref()
    }

    #[must_use]
    pub fn findings(&self) -> &[HealthFinding] {
        &self.findings
    }
}

#[derive(Clone, Debug)]
pub struct HealthFindingGetRequest {
    finding_id: String,
}

impl HealthFindingGetRequest {
    pub fn try_new(finding_id: impl Into<String>) -> DepgraphServiceResult<Self> {
        let finding_id = finding_id.into();
        if !finding_id.starts_with("finding:sha256:")
            || finding_id.len() > 160
            || finding_id.chars().any(char::is_control)
        {
            return Err(DepgraphServiceError::InvalidInput);
        }
        Ok(Self { finding_id })
    }

    #[must_use]
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }
}

#[derive(Clone, Debug)]
pub struct HealthAuditRequest {
    changed_ref: String,
    base_snapshot: Option<String>,
}

impl HealthAuditRequest {
    pub fn try_new(
        changed_ref: impl Into<String>,
        base_snapshot: Option<String>,
    ) -> DepgraphServiceResult<Self> {
        let changed_ref = changed_ref.into();
        if !valid_git_ref(&changed_ref) {
            return Err(DepgraphServiceError::InvalidInput);
        }
        if let Some(base) = &base_snapshot
            && (base.is_empty() || base.len() > 256 || base.chars().any(char::is_control))
        {
            return Err(DepgraphServiceError::InvalidInput);
        }
        Ok(Self {
            changed_ref,
            base_snapshot,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PinnedHealthSnapshot {
    id: ResolvedSnapshotId,
    snapshot: GraphSnapshot,
}

impl PinnedHealthSnapshot {
    #[must_use]
    pub const fn id(&self) -> &ResolvedSnapshotId {
        &self.id
    }

    #[must_use]
    pub const fn snapshot(&self) -> &GraphSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.snapshot.scan.id
    }
}

#[derive(Clone, Debug)]
pub struct HealthAuditReadScope {
    after: PinnedHealthSnapshot,
    before: Option<PinnedHealthSnapshot>,
    changed_set: GitChangedSet,
    changed_set_digest: String,
    comparability: AuditComparability,
    boundary_violation_ids: BTreeSet<String>,
    policy_config_digest: String,
}

impl HealthAuditReadScope {
    #[must_use]
    pub const fn after(&self) -> &PinnedHealthSnapshot {
        &self.after
    }

    #[must_use]
    pub const fn before(&self) -> Option<&PinnedHealthSnapshot> {
        self.before.as_ref()
    }

    #[must_use]
    pub fn comparable_pair(&self) -> Option<(&PinnedHealthSnapshot, &PinnedHealthSnapshot)> {
        self.before.as_ref().map(|before| (before, &self.after))
    }

    #[must_use]
    pub fn changed_oid(&self) -> &str {
        &self.changed_set.head
    }

    #[must_use]
    pub fn policy_config_digest(&self) -> &str {
        &self.policy_config_digest
    }
}

#[derive(Clone, Debug)]
pub struct HealthAuditResult {
    after_snapshot_id: ResolvedSnapshotId,
    before_snapshot_id: Option<ResolvedSnapshotId>,
    changed_oid: String,
    collection_digest: String,
    findings: Vec<HealthFinding>,
}

impl HealthAuditResult {
    #[must_use]
    pub const fn after_snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.after_snapshot_id
    }

    #[must_use]
    pub const fn before_snapshot_id(&self) -> Option<&ResolvedSnapshotId> {
        self.before_snapshot_id.as_ref()
    }

    #[must_use]
    pub fn changed_oid(&self) -> &str {
        &self.changed_oid
    }

    #[must_use]
    pub fn collection_digest(&self) -> &str {
        &self.collection_digest
    }

    #[must_use]
    pub fn findings(&self) -> &[HealthFinding] {
        &self.findings
    }
}

#[derive(Clone, Debug)]
pub struct HealthHotspotsRequest {
    churn_commit_limit: u32,
    churn_path_filter: Vec<String>,
    weights: HotspotWeights,
}

impl HealthHotspotsRequest {
    pub fn try_new(
        churn_commit_limit: u32,
        churn_path_filter: Vec<String>,
        weights: HotspotWeights,
    ) -> DepgraphServiceResult<Self> {
        if !(1..=MAX_HEALTH_CHURN_COMMITS).contains(&churn_commit_limit)
            || churn_path_filter.len() > MAX_HEALTH_FILTER_ITEMS
        {
            return Err(DepgraphServiceError::InvalidInput);
        }
        let mut churn_path_filter = churn_path_filter
            .into_iter()
            .map(|path| {
                if path.len() > 512 || path.chars().any(char::is_control) {
                    return Err(DepgraphServiceError::InvalidInput);
                }
                RepositoryRelativePath::parse(&path)
                    .map(|normalized| normalized.as_str().to_owned())
                    .map_err(|_| DepgraphServiceError::InvalidInput)
            })
            .collect::<DepgraphServiceResult<Vec<_>>>()?;
        churn_path_filter.sort();
        churn_path_filter.dedup();
        Ok(Self {
            churn_commit_limit,
            churn_path_filter,
            weights,
        })
    }

    #[must_use]
    pub const fn churn_commit_limit(&self) -> u32 {
        self.churn_commit_limit
    }

    #[must_use]
    pub fn churn_path_filter(&self) -> &[String] {
        &self.churn_path_filter
    }

    #[must_use]
    pub const fn weights(&self) -> HotspotWeights {
        self.weights
    }
}

#[derive(Clone, Debug)]
pub struct HealthHotspotsResult {
    snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    collection_digest: String,
    findings: Vec<HealthFinding>,
}

impl HealthHotspotsResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub fn collection_digest(&self) -> &str {
        &self.collection_digest
    }

    #[must_use]
    pub fn findings(&self) -> &[HealthFinding] {
        &self.findings
    }
}

impl DepgraphService {
    pub fn health_summary(
        &self,
        snapshot_request: &mut SnapshotReadRequest,
        request: &HealthSummaryRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<HealthSummaryResult> {
        let snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot = load_pinned_snapshot(snapshot_request, cancellation)?;
        let collected =
            collect_snapshot_scoped(&snapshot, self.config().canonical_root(), cancellation)?;
        let filtered = collected.findings.into_iter().filter(|finding| {
            request
                .kinds
                .as_ref()
                .is_none_or(|kinds| kinds.contains(&finding.kind))
        });
        let mut counts_by_kind = BTreeMap::new();
        let mut counts_by_confidence = BTreeMap::new();
        let mut ids = Vec::new();
        for finding in filtered {
            *counts_by_kind
                .entry(finding.kind.as_str().to_owned())
                .or_insert(0) += 1;
            *counts_by_confidence
                .entry(finding.confidence.as_str().to_owned())
                .or_insert(0) += 1;
            ids.push(finding.id);
        }
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let collection_digest = collection_digest(
            &CollectionIdentity {
                snapshot_ids: vec![snapshot_id.as_str().to_owned()],
                manifest_digest: collected.manifest_digest.clone(),
                changed_oid: None,
                changed_set_digest: None,
                churn_start_oid: None,
                churn_commit_limit: None,
                churn_path_filter: Vec::new(),
                hotspot_weights: None,
            },
            &ids,
        );
        Ok(HealthSummaryResult {
            snapshot_id,
            scan_id: snapshot.scan.id,
            collection_digest,
            manifest_digest: collected.manifest_digest,
            counts_by_kind,
            counts_by_confidence,
            coverage: HealthCoverageOverview {
                completeness: snapshot.coverage.completeness,
                files_skipped: snapshot.coverage.files_skipped,
                unresolved: snapshot.coverage.unresolved,
                candidates: snapshot.coverage.candidates,
            },
        })
    }

    pub fn health_findings(
        &self,
        snapshot_request: &mut SnapshotReadRequest,
        request: &HealthFindingsRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<HealthFindingsResult> {
        let snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot = load_pinned_snapshot(snapshot_request, cancellation)?;
        let collected =
            collect_snapshot_scoped(&snapshot, self.config().canonical_root(), cancellation)?;
        let mut findings = collected.findings;
        findings.retain(|finding| {
            (request.kinds.is_empty() || request.kinds.contains(&finding.kind))
                && (request.severities.is_empty() || request.severities.contains(&finding.severity))
                && (request.confidences.is_empty()
                    || request.confidences.contains(&finding.confidence))
        });
        findings.sort_by(|left, right| left.id.cmp(&right.id));
        if findings.len() > request.limit {
            findings.truncate(request.limit);
        }
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let ids = findings
            .iter()
            .map(|finding| finding.id.clone())
            .collect::<Vec<_>>();
        let collection_digest = collection_digest(
            &CollectionIdentity {
                snapshot_ids: vec![snapshot_id.as_str().to_owned()],
                manifest_digest: collected.manifest_digest.clone(),
                changed_oid: None,
                changed_set_digest: None,
                churn_start_oid: None,
                churn_commit_limit: None,
                churn_path_filter: Vec::new(),
                hotspot_weights: None,
            },
            &ids,
        );
        Ok(HealthFindingsResult {
            snapshot_id,
            scan_id: snapshot.scan.id,
            collection_digest,
            manifest_digest: collected.manifest_digest,
            findings,
        })
    }

    pub fn health_finding_get(
        &self,
        snapshot_request: &mut SnapshotReadRequest,
        request: &HealthFindingGetRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<HealthFindingDetail> {
        let result = self.health_findings(
            snapshot_request,
            &HealthFindingsRequest::try_new(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                MAX_HEALTH_FINDINGS,
            )?,
            cancellation,
        )?;
        let Some(finding) = result
            .findings
            .into_iter()
            .find(|finding| finding.id == request.finding_id)
        else {
            return Err(DepgraphServiceError::InvalidInput);
        };
        Ok(HealthFindingDetail {
            finding,
            input_scope: crate::health::FindingKindScope::SnapshotScoped,
        })
    }

    pub fn start_health_audit_scope(
        &self,
        after_request: &mut SnapshotReadRequest,
        request: &HealthAuditRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<HealthAuditReadScope> {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        // Read and evaluate policy once while opening the scope.  The
        // resulting boundary IDs remain stable even if repository config is
        // edited before a caller consumes the pinned scope.
        let policy = self.read_policy_config(cancellation)?;
        let policy_config_digest = policy
            .normalized_identity()
            .map(|value| stable_id_from_value("policy-config", &value))
            .map_err(|_| DepgraphServiceError::Internal)?;
        let after_id = after_request.snapshot_id().clone();
        let after = load_pinned_snapshot(after_request, cancellation)?;
        let changed_set = read_git_changed_set_cancellable(
            self.config().canonical_root(),
            &request.changed_ref,
            || cancellation.is_cancelled(),
        )
        .map_err(|error| map_git_query_error(&error, cancellation))?;
        let changed_set_digest = changed_set_digest(&changed_set);
        let worktree_dirty = changed_set
            .changes
            .iter()
            .any(|change| change.sources.iter().any(|source| source == "worktree"))
            || after.scan.source_revision.as_deref() != Some(changed_set.head.as_str());
        let mut comparability = AuditComparability {
            worktree_dirty,
            ..AuditComparability::default()
        };
        let before = resolve_before_snapshot(
            after_request,
            request.base_snapshot.as_deref(),
            &changed_set.merge_base,
            &mut comparability,
            cancellation,
        )?;
        if let Some(before) = &before {
            comparability.profile_matrix_changed = before.snapshot.profile_matrix.schema_version
                != after.profile_matrix.schema_version
                || profile_matrix_identities(&before.snapshot, cancellation)?
                    != profile_matrix_identities(&after, cancellation)?
                || profile_identities(&before.snapshot, cancellation)?
                    != profile_identities(&after, cancellation)?;
            comparability.coverage_retreated = completeness_rank(&after.coverage.completeness)
                < completeness_rank(&before.snapshot.coverage.completeness);
        } else {
            comparability.missing_base = true;
        }
        let boundary_violation_ids = evaluate_audit_boundary_ids(
            &policy,
            before.as_ref(),
            &PinnedHealthSnapshot {
                id: after_id.clone(),
                snapshot: after.clone(),
            },
            cancellation,
        )?;
        Ok(HealthAuditReadScope {
            after: PinnedHealthSnapshot {
                id: after_id,
                snapshot: after,
            },
            before,
            changed_set,
            changed_set_digest,
            comparability,
            boundary_violation_ids,
            policy_config_digest,
        })
    }

    pub fn health_audit(
        &self,
        scope: &HealthAuditReadScope,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<HealthAuditResult> {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut changed_nodes = BTreeSet::new();
        let before_for_blast = scope
            .before
            .as_ref()
            .filter(|_| !scope.comparability.base_mismatch);
        for snapshot in std::iter::once(scope.after.snapshot())
            .chain(before_for_blast.map(PinnedHealthSnapshot::snapshot))
        {
            let mut cancelled = || cancellation.is_cancelled();
            let mappings =
                map_changed_set_cancellable(snapshot, &scope.changed_set, &mut cancelled).map_err(
                    |error| {
                        if is_resource_exhausted(&error) {
                            DepgraphServiceError::ResourceExhausted
                        } else if cancellation.is_cancelled() {
                            DepgraphServiceError::Cancelled
                        } else {
                            DepgraphServiceError::graph_query(error)
                        }
                    },
                )?;
            for mapping in mappings {
                changed_nodes.extend(mapping.new_node_ids);
                changed_nodes.extend(mapping.old_node_ids);
                changed_nodes.extend(mapping.correlated_node_ids);
            }
        }
        let changed_nodes = changed_nodes.into_iter().collect::<Vec<_>>();
        let findings = bound_findings(
            analyze_changed_code_with_boundary_ids_cancellable(
                scope.after.snapshot(),
                scope.before.as_ref().map(PinnedHealthSnapshot::snapshot),
                &changed_nodes,
                &scope.comparability,
                AuditAnalysisOptions {
                    boundary_violation_ids: &scope.boundary_violation_ids,
                    maximum_findings: MAX_HEALTH_FINDINGS,
                    maximum_work: MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
                },
                || cancellation.is_cancelled(),
            )
            .map_err(map_health_analysis_error)?,
        )?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut snapshot_ids = Vec::with_capacity(2);
        if let Some(before) = &scope.before {
            snapshot_ids.push(before.id.as_str().to_owned());
        }
        snapshot_ids.push(scope.after.id.as_str().to_owned());
        let ids = findings
            .iter()
            .map(|finding| finding.id.clone())
            .collect::<Vec<_>>();
        Ok(HealthAuditResult {
            after_snapshot_id: scope.after.id.clone(),
            before_snapshot_id: scope.before.as_ref().map(|before| before.id.clone()),
            changed_oid: scope.changed_set.head.clone(),
            collection_digest: collection_digest_with_policy(
                &CollectionIdentity {
                    snapshot_ids,
                    manifest_digest: None,
                    changed_oid: Some(scope.changed_set.head.clone()),
                    changed_set_digest: Some(scope.changed_set_digest.clone()),
                    churn_start_oid: None,
                    churn_commit_limit: None,
                    churn_path_filter: Vec::new(),
                    hotspot_weights: None,
                },
                &ids,
                &scope.policy_config_digest,
            ),
            findings,
        })
    }

    pub fn health_hotspots(
        &self,
        snapshot_request: &mut SnapshotReadRequest,
        request: &HealthHotspotsRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<HealthHotspotsResult> {
        let snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot = load_pinned_snapshot(snapshot_request, cancellation)?;
        let (churn, churn_oid, churn_ok) = collect_churn(
            self.config().canonical_root(),
            request.churn_commit_limit,
            &request.churn_path_filter,
            cancellation,
        )?;
        let runtime = collect_runtime_observations(&snapshot, cancellation)?;
        let availability = HotspotLayerAvailability {
            churn: churn_ok,
            runtime: !runtime.is_empty(),
        };
        let findings = score_hotspots_cancellable(
            &snapshot,
            request.weights,
            &churn,
            &runtime,
            availability,
            MAX_HEALTH_FINDINGS,
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
            || cancellation.is_cancelled(),
        )
        .map_err(|error| match error {
            HotspotAnalysisError::Cancelled => DepgraphServiceError::Cancelled,
            HotspotAnalysisError::ResourceExhausted => DepgraphServiceError::ResourceExhausted,
        })?;
        let findings = bound_findings(findings)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let ids = findings
            .iter()
            .map(|finding| finding.id.clone())
            .collect::<Vec<_>>();
        Ok(HealthHotspotsResult {
            snapshot_id: snapshot_id.clone(),
            scan_id: snapshot.scan.id,
            collection_digest: collection_digest(
                &CollectionIdentity {
                    snapshot_ids: vec![snapshot_id.as_str().to_owned()],
                    manifest_digest: None,
                    changed_oid: None,
                    changed_set_digest: None,
                    churn_start_oid: churn_oid,
                    churn_commit_limit: Some(request.churn_commit_limit),
                    churn_path_filter: request.churn_path_filter.clone(),
                    hotspot_weights: Some(request.weights.as_map()),
                },
                &ids,
            ),
            findings,
        })
    }
}

fn evaluate_audit_boundary_ids(
    policy: &PolicyConfig,
    before: Option<&PinnedHealthSnapshot>,
    after: &PinnedHealthSnapshot,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<BTreeSet<String>> {
    evaluate_audit_boundary_ids_with_limit(
        policy,
        before,
        after,
        cancellation,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
    )
}

fn evaluate_audit_boundary_ids_with_limit(
    policy: &PolicyConfig,
    before: Option<&PinnedHealthSnapshot>,
    after: &PinnedHealthSnapshot,
    cancellation: &CancellationToken,
    maximum_work: usize,
) -> DepgraphServiceResult<BTreeSet<String>> {
    let has_boundary_rule = policy.rules.iter().any(|rule| {
        matches!(
            rule.kind,
            crate::policy::PolicyRuleKind::LayerBoundary
                | crate::policy::PolicyRuleKind::ForbiddenDependency
                | crate::policy::PolicyRuleKind::RuntimeBoundary
        )
    });
    if !has_boundary_rule {
        return Ok(BTreeSet::new());
    }
    let Some(before) = before else {
        return Ok(BTreeSet::new());
    };
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    preflight_graph_work(
        before.snapshot(),
        after.snapshot(),
        policy.rules.len().saturating_add(1),
        cancellation,
    )?;
    evaluate_boundary_violation_ids_cancellable(
        before.id().as_str(),
        before.snapshot(),
        after.id().as_str(),
        after.snapshot(),
        policy,
        maximum_work,
        || cancellation.is_cancelled(),
    )
    .map_err(|source| {
        if is_policy_evaluation_resource_exhausted(&source) {
            DepgraphServiceError::ResourceExhausted
        } else if is_policy_evaluation_cancelled(&source) || cancellation.is_cancelled() {
            DepgraphServiceError::Cancelled
        } else {
            DepgraphServiceError::PolicyInput
        }
    })
}

struct SnapshotScopedCollection {
    findings: Vec<HealthFinding>,
    manifest_digest: Option<String>,
}

fn collect_snapshot_scoped(
    snapshot: &GraphSnapshot,
    root: &Path,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<SnapshotScopedCollection> {
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    let manifests = load_manifests(root, snapshot, cancellation)?;
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    let mut findings = analyze_unused_cancellable(
        snapshot,
        MAX_HEALTH_FINDINGS,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        || cancellation.is_cancelled(),
    )
    .map_err(map_health_analysis_error)?;
    let remaining = MAX_HEALTH_FINDINGS.saturating_sub(findings.len());
    findings.extend(
        analyze_dependencies_cancellable(
            snapshot,
            &manifests,
            remaining,
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
            || cancellation.is_cancelled(),
        )
        .map_err(map_health_analysis_error)?,
    );
    findings.retain(|finding| finding.kind.is_snapshot_scoped());
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(SnapshotScopedCollection {
        findings: bound_findings(findings)?,
        manifest_digest: manifests_digest(&manifests),
    })
}

fn map_health_analysis_error(error: HealthAnalysisError) -> DepgraphServiceError {
    match error {
        HealthAnalysisError::Cancelled => DepgraphServiceError::Cancelled,
        HealthAnalysisError::ResourceExhausted => DepgraphServiceError::ResourceExhausted,
        HealthAnalysisError::Integrity => DepgraphServiceError::Integrity,
    }
}

fn manifests_digest(manifests: &[crate::health::ManifestIdentity]) -> Option<String> {
    if manifests.is_empty() {
        return None;
    }
    let payload = serde_json::json!(
        manifests
            .iter()
            .map(|manifest| serde_json::json!({
                "digest": manifest.digest,
                "drifted": manifest.drifted,
                "path": manifest.path,
            }))
            .collect::<Vec<_>>()
    );
    Some(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            depgraph_protocol::canonical_json(&payload).as_bytes()
        ))
    ))
}

fn bound_findings(findings: Vec<HealthFinding>) -> DepgraphServiceResult<Vec<HealthFinding>> {
    if findings.len() > MAX_HEALTH_FINDINGS {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    if findings.iter().any(|finding| {
        finding.blockers.len() > MAX_HEALTH_BLOCKERS_PER_FINDING
            || finding.evidence.len() > MAX_HEALTH_EVIDENCE_PER_FINDING
            || finding.remediations.len() > MAX_HEALTH_REMEDIATIONS_PER_FINDING
            || finding.suppressions.len() > MAX_HEALTH_SUPPRESSIONS_PER_FINDING
    }) {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    Ok(findings)
}

fn load_manifests(
    root: &Path,
    snapshot: &GraphSnapshot,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<Vec<ManifestIdentity>> {
    let mut paths = crate::health::dependency::manifest_paths_cancellable(
        snapshot,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        || cancellation.is_cancelled(),
    )
    .map_err(map_health_analysis_error)?;
    for default in ["Cargo.toml", "go.mod", "package.json"] {
        if fs::symlink_metadata(root.join(default)).is_ok() {
            paths.insert(default.to_owned());
        }
    }
    if paths.len() > MAX_HEALTH_MANIFESTS {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    let mut snapshot_hashes_by_path = BTreeMap::<String, BTreeSet<String>>::new();
    let mut snapshot_hash_work = 0_usize;
    for node in &snapshot.nodes {
        health_service_step(
            &mut snapshot_hash_work,
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
            cancellation,
        )?;
        let Some(hash) = ["content_hash", "content_digest"]
            .into_iter()
            .find_map(|key| node.properties.get(key).and_then(serde_json::Value::as_str))
        else {
            continue;
        };
        for key in ["path", "manifest_path"] {
            if let Some(path) = node.properties.get(key).and_then(serde_json::Value::as_str) {
                snapshot_hashes_by_path
                    .entry(path.to_owned())
                    .or_default()
                    .insert(hash.to_owned());
            }
        }
    }
    let mut manifests = Vec::new();
    let mut total_bytes = 0_usize;
    for path in paths {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let relative =
            RepositoryRelativePath::parse(&path).map_err(|_| DepgraphServiceError::InvalidInput)?;
        match read_confined_manifest(root, relative.as_str()) {
            Ok((digest, bytes)) => {
                total_bytes = total_bytes
                    .checked_add(bytes.len())
                    .filter(|total| *total <= MAX_HEALTH_TOTAL_MANIFEST_BYTES)
                    .ok_or(DepgraphServiceError::ResourceExhausted)?;
                let declared = parse_declared_dependencies(&path, &bytes);
                let drifted =
                    snapshot_hashes_by_path
                        .get(path.as_str())
                        .is_none_or(|snapshot_hashes| {
                            snapshot_hashes.len() != 1 || !snapshot_hashes.contains(&digest)
                        })
                        || declared.is_none();
                manifests.push(ManifestIdentity {
                    path,
                    digest,
                    declared: declared.unwrap_or_default(),
                    drifted,
                });
            }
            Err(diagnostic)
                if matches!(
                    diagnostic.code,
                    "query_file_unavailable"
                        | "query_file_not_regular"
                        | "query_file_changed_during_open"
                        | "query_file_changed_during_read"
                        | "query_file_metadata_unavailable"
                        | "query_file_read_failed"
                        | "query_file_symlink_rejected"
                        | "query_file_open_failed"
                ) =>
            {
                manifests.push(ManifestIdentity {
                    path,
                    digest: "unavailable".to_owned(),
                    declared: BTreeSet::new(),
                    drifted: true,
                });
            }
            Err(diagnostic)
                if diagnostic.class == QueryFailureClass::Limit
                    || diagnostic.code == "query_file_size_or_type_invalid" =>
            {
                return Err(DepgraphServiceError::ResourceExhausted);
            }
            Err(_) => return Err(DepgraphServiceError::InvalidInput),
        }
    }
    Ok(manifests)
}

fn health_service_step(
    used: &mut usize,
    maximum: usize,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<()> {
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    if *used >= maximum {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    *used += 1;
    Ok(())
}

fn read_confined_manifest(
    root: &Path,
    relative: &str,
) -> Result<(String, Vec<u8>), crate::QueryDiagnostic> {
    let bytes = read_bounded_repository_file(root, Path::new(relative), MAX_HEALTH_MANIFEST_BYTES)?;
    Ok((
        format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        bytes,
    ))
}

fn parse_declared_dependencies(path: &str, bytes: &[u8]) -> Option<BTreeSet<String>> {
    let text = std::str::from_utf8(bytes).ok()?;
    match Path::new(path).file_name().and_then(|name| name.to_str()) {
        Some("Cargo.toml") => parse_cargo_dependencies(text),
        Some("go.mod") => parse_go_mod(text),
        Some("package.json") => parse_package_json(text),
        _ if text.trim_start().starts_with('{') => parse_package_json(text),
        _ if text.lines().any(|line| {
            let line = line.trim();
            line.starts_with("module ") || line.starts_with("go ") || line.starts_with("require ")
        }) =>
        {
            parse_go_mod(text)
        }
        _ => parse_cargo_dependencies(text),
    }
}

fn parse_cargo_dependencies(text: &str) -> Option<BTreeSet<String>> {
    let value = toml::from_str::<toml::Value>(text).ok()?;
    let mut names = BTreeSet::new();
    for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
        extend_cargo_dependency_table(&mut names, value.get(table));
    }
    if let Some(workspace) = value.get("workspace") {
        extend_cargo_dependency_table(&mut names, workspace.get("dependencies"));
    }
    if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
                extend_cargo_dependency_table(&mut names, target.get(table));
            }
        }
    }
    Some(names)
}

fn extend_cargo_dependency_table(names: &mut BTreeSet<String>, value: Option<&toml::Value>) {
    if let Some(dependencies) = value.and_then(toml::Value::as_table) {
        names.extend(dependencies.keys().cloned());
    }
}

fn parse_go_mod(text: &str) -> Option<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut in_require_block = false;
    for raw in text.lines() {
        let line = raw
            .split_once("//")
            .map_or(raw, |(before, _)| before)
            .trim();
        if in_require_block {
            if line == ")" {
                in_require_block = false;
            } else if !line.is_empty() {
                let mut fields = line.split_whitespace();
                let (Some(name), Some(_version)) = (fields.next(), fields.next()) else {
                    return None;
                };
                names.insert(name.to_owned());
            }
            continue;
        }
        let Some(requirement) = line.strip_prefix("require ") else {
            continue;
        };
        let requirement = requirement.trim();
        if requirement == "(" {
            in_require_block = true;
        } else {
            let mut fields = requirement.split_whitespace();
            let (Some(name), Some(_version)) = (fields.next(), fields.next()) else {
                return None;
            };
            names.insert(name.to_owned());
        }
    }
    (!in_require_block).then_some(names)
}

fn parse_package_json(text: &str) -> Option<BTreeSet<String>> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    value.as_object()?;
    let mut names = BTreeSet::new();
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(section) = value.get(key) {
            let deps = section.as_object()?;
            names.extend(deps.keys().cloned());
        }
    }
    Some(names)
}

fn resolve_before_snapshot(
    after_request: &mut SnapshotReadRequest,
    explicit: Option<&str>,
    target_oid: &str,
    comparability: &mut AuditComparability,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<Option<PinnedHealthSnapshot>> {
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    if let Some(explicit) = explicit {
        let locator = SnapshotLocator::parse(explicit)?;
        let id = match &locator {
            SnapshotLocator::StableId(id) => ResolvedSnapshotId::from_completed(id.clone())?,
            SnapshotLocator::Current => after_request.snapshot_id().clone(),
            SnapshotLocator::Name(name) => {
                let cancellation_check = cancellation.clone();
                let resolved = after_request.store().interruptible_read(
                    move || cancellation_check.is_cancelled(),
                    |store| store.snapshot_id_for_name(name),
                );
                let id = resolved
                    .map_err(DepgraphServiceError::store_operation)?
                    .ok_or(DepgraphServiceError::NotFound)?;
                ResolvedSnapshotId::from_completed(id)?
            }
        };
        let loaded = load_snapshot_by_id(after_request, id.as_str(), cancellation)?;
        if loaded.scan.source_revision.as_deref() != Some(target_oid) {
            comparability.base_mismatch = true;
        }
        return Ok(Some(PinnedHealthSnapshot {
            id,
            snapshot: loaded,
        }));
    }
    let target_oid = target_oid.to_owned();
    let cancellation_check = cancellation.clone();
    let id = after_request
        .store()
        .interruptible_read(
            move || cancellation_check.is_cancelled(),
            |store| store.first_completed_snapshot_id_for_source_revision(&target_oid),
        )
        .map_err(DepgraphServiceError::store_operation)?;
    let Some(id) = id else {
        return Ok(None);
    };
    let loaded = load_snapshot_by_id(after_request, &id, cancellation)?;
    Ok(Some(PinnedHealthSnapshot {
        id: ResolvedSnapshotId::from_completed(id)?,
        snapshot: loaded,
    }))
}

fn load_snapshot_by_id(
    request: &mut SnapshotReadRequest,
    snapshot_id: &str,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<GraphSnapshot> {
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    let id = snapshot_id.to_owned();
    let cancellation_check = cancellation.clone();
    request
        .store()
        .interruptible_read(
            move || cancellation_check.is_cancelled(),
            move |store| store.load_completed_snapshot(&id),
        )
        .map_err(DepgraphServiceError::store_operation)
}

fn completeness_rank(levels: &[String]) -> u8 {
    if levels
        .iter()
        .any(|level| level.contains("semantic-complete"))
    {
        2
    } else if levels.iter().any(|level| level.contains("syntax-complete")) {
        1
    } else {
        0
    }
}

fn valid_git_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GIT_REF_BYTES
        && !value.starts_with('-')
        && !value.chars().any(char::is_control)
}

fn profile_identities(
    snapshot: &GraphSnapshot,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<BTreeSet<(String, String)>> {
    let mut identities = BTreeSet::new();
    let mut work = 0_usize;
    for profile in &snapshot.profiles {
        health_service_step(
            &mut work,
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
            cancellation,
        )?;
        identities.insert((profile.id.clone(), profile.language.clone()));
    }
    Ok(identities)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProfileMatrixIdentity {
    entry_id: String,
    effective_input_id: String,
    language: String,
    profile_ids: Vec<String>,
    parent_profile_ids: Vec<String>,
    phases: Vec<String>,
    selection_reasons: Vec<String>,
}

fn profile_matrix_identities(
    snapshot: &GraphSnapshot,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<BTreeSet<ProfileMatrixIdentity>> {
    let mut identities = BTreeSet::new();
    let mut work = 0_usize;
    for entry in &snapshot.profile_matrix.entries {
        health_service_step(
            &mut work,
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
            cancellation,
        )?;
        identities.insert(ProfileMatrixIdentity {
            entry_id: entry.id.clone(),
            effective_input_id: entry.effective_input_id.clone(),
            language: entry.language.clone(),
            profile_ids: entry.profile_ids.clone(),
            parent_profile_ids: entry.parent_profile_ids.clone(),
            phases: entry.phases.clone(),
            selection_reasons: entry.selection_reasons.clone(),
        });
    }
    Ok(identities)
}

fn changed_set_digest(changed_set: &GitChangedSet) -> String {
    let payload = serde_json::json!({
        "changes": changed_set.changes,
        "head": changed_set.head,
        "merge_base": changed_set.merge_base,
        "repository_prefix": changed_set.repository_prefix,
        "resolved_ref": changed_set.resolved_ref,
    });
    format!(
        "changed-set:sha256:{}",
        hex::encode(Sha256::digest(
            depgraph_protocol::canonical_json(&payload).as_bytes()
        ))
    )
}

fn map_git_query_error(
    error: &anyhow::Error,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    if cancellation.is_cancelled() {
        DepgraphServiceError::Cancelled
    } else if is_resource_exhausted(error) {
        DepgraphServiceError::ResourceExhausted
    } else {
        DepgraphServiceError::InvalidInput
    }
}

fn collect_churn(
    root: &Path,
    limit: u32,
    path_filter: &[String],
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<(BTreeMap<String, u64>, Option<String>, bool)> {
    match read_git_churn_cancellable(root, limit, path_filter, || cancellation.is_cancelled()) {
        Ok(churn) => Ok((churn.counts_by_path, Some(churn.head), true)),
        Err(_) if cancellation.is_cancelled() => Err(DepgraphServiceError::Cancelled),
        Err(_) => Ok((BTreeMap::new(), None, false)),
    }
}

fn collect_runtime_observations(
    snapshot: &GraphSnapshot,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<BTreeMap<String, u64>> {
    let mut counts = BTreeMap::<String, u64>::new();
    let mut work = 0_usize;
    for edge in &snapshot.edges {
        health_service_step(
            &mut work,
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
            cancellation,
        )?;
        if edge.phase == "runtime" {
            *counts.entry(edge.source.clone()).or_insert(0) += 1;
            *counts.entry(edge.target.clone()).or_insert(0) += 1;
        }
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use depgraph_protocol::{EvidenceKind, Precision, ResolutionStatus};
    use depgraph_store::{CoverageRecord, ProfileMatrixRecord};

    use super::*;
    use crate::health::DEFAULT_HOTSPOT_WEIGHTS;
    use crate::policy::{
        POLICY_SCHEMA_VERSION, PolicyCondition, PolicyEvidenceRequirement, PolicyMatchKind,
        PolicyProfileFilter, PolicyRule, PolicyRuleKind, PolicySelector, PolicySelectorCardinality,
        PolicySelectorField, PolicySelectorKind, PolicySelectorScope,
    };

    fn bounded_runtime_policy() -> PolicyConfig {
        let selector = |value: &str, cardinality| PolicySelector {
            kind: PolicySelectorKind::Component,
            field: PolicySelectorField::Locator,
            match_kind: PolicyMatchKind::Prefix,
            value: value.to_owned(),
            cardinality,
            exclude: Vec::new(),
            scope: PolicySelectorScope::default(),
        };
        PolicyConfig {
            schema_version: POLICY_SCHEMA_VERSION.to_owned(),
            rules: vec![PolicyRule {
                id: "health-runtime-boundary".to_owned(),
                kind: PolicyRuleKind::RuntimeBoundary,
                severity: crate::policy::PolicySeverity::Error,
                source: selector("component:source-", PolicySelectorCardinality::Many),
                target: selector("component:boundary", PolicySelectorCardinality::One),
                profiles: PolicyProfileFilter::default(),
                condition: PolicyCondition::default(),
                precisions: vec![Precision::Exact],
                resolution_statuses: vec![ResolutionStatus::Resolved],
                evidence: PolicyEvidenceRequirement {
                    kinds: vec![EvidenceKind::Source],
                    minimum_spans: 1,
                    primary_only: true,
                },
                threshold: None,
            }],
            suppressions: Vec::new(),
        }
    }

    fn empty_snapshot() -> GraphSnapshot {
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan:health-limit-test".to_owned(),
                root: "/health-limit-test".to_owned(),
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

    fn pinned_snapshot(digest: char) -> PinnedHealthSnapshot {
        let stable_id = format!("snapshot:sha256:{}", digest.to_string().repeat(64));
        PinnedHealthSnapshot {
            id: ResolvedSnapshotId::from_completed(stable_id).expect("stable test snapshot ID"),
            snapshot: empty_snapshot(),
        }
    }

    #[test]
    fn issue_439_health_boundary_maps_policy_budget_and_cancellation() {
        let policy = bounded_runtime_policy();
        let before = pinned_snapshot('a');
        let after = pinned_snapshot('b');
        let live = CancellationToken::new();
        let exhausted =
            evaluate_audit_boundary_ids_with_limit(&policy, Some(&before), &after, &live, 0);
        assert!(matches!(
            exhausted,
            Err(DepgraphServiceError::ResourceExhausted)
        ));

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            evaluate_audit_boundary_ids_with_limit(
                &policy,
                Some(&before),
                &after,
                &cancelled,
                usize::MAX,
            ),
            Err(DepgraphServiceError::Cancelled)
        ));
    }

    #[test]
    fn issue_423_manifest_parsers_cover_declared_sections_only() {
        let go = parse_go_mod(
            r#"
module example.test/app
go 1.26
require example.test/direct v1.0.0
require (
    example.test/block v2.0.0
)
replace (
    example.test/old => example.test/new v1.0.0
)
exclude example.test/excluded v1.2.3
"#,
        )
        .expect("valid go.mod");
        assert_eq!(
            go,
            BTreeSet::from([
                "example.test/block".to_owned(),
                "example.test/direct".to_owned(),
            ])
        );

        let cargo = parse_cargo_dependencies(
            r#"
[workspace]
members = []
[workspace.dependencies]
serde = "1"
[target."cfg(unix)".dependencies]
libc = "1"
"#,
        )
        .expect("valid Cargo.toml");
        assert_eq!(
            cargo,
            BTreeSet::from(["libc".to_owned(), "serde".to_owned()])
        );

        let package =
            parse_package_json(r#"{"dependencies":{"prod":"1"},"devDependencies":{"test":"1"}}"#)
                .expect("valid package.json");
        assert_eq!(
            package,
            BTreeSet::from(["prod".to_owned(), "test".to_owned()])
        );

        assert!(parse_cargo_dependencies("[dependencies\nserde = 1").is_none());
        assert!(parse_go_mod("module example.test/app\nrequire (\n x.test/y v1").is_none());
        assert!(parse_package_json(r#"{"dependencies":[]}"#).is_none());
    }

    #[test]
    fn issue_423_hotspot_paths_are_repository_relative_and_canonical() {
        assert!(
            HealthHotspotsRequest::try_new(
                8,
                vec!["../outside".to_owned()],
                DEFAULT_HOTSPOT_WEIGHTS,
            )
            .is_err()
        );
        assert!(
            HealthHotspotsRequest::try_new(
                8,
                vec!["/absolute".to_owned()],
                DEFAULT_HOTSPOT_WEIGHTS,
            )
            .is_err()
        );
        let request = HealthHotspotsRequest::try_new(
            8,
            vec!["src/lib.rs".to_owned(), "src/lib.rs".to_owned()],
            DEFAULT_HOTSPOT_WEIGHTS,
        )
        .expect("valid hotspot request");
        assert_eq!(request.churn_path_filter(), ["src/lib.rs"]);
    }

    #[cfg(unix)]
    #[test]
    fn issue_423_manifest_reader_rejects_symlink_components() {
        use std::os::unix::fs::symlink;

        let repository = tempfile::tempdir().expect("repository");
        let outside = tempfile::tempdir().expect("outside");
        fs::write(
            outside.path().join("Cargo.toml"),
            "[dependencies]\nserde = \"1\"\n",
        )
        .expect("outside manifest");
        symlink(outside.path(), repository.path().join("linked")).expect("symlink");
        let error = read_confined_manifest(repository.path(), "linked/Cargo.toml")
            .expect_err("symlinked manifest must fail closed");
        assert_eq!(error.class, QueryFailureClass::Security);
    }
}
