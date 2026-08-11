use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::{self, Read, Write},
};

use depgraph_protocol::{EvidenceKind, stable_id_from_value};
use depgraph_store::{
    CoverageRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, GraphSnapshotDiff, NodeRecord,
    NodeRename, ProfileRecord, RecordDiff, RenameConfidence, SiteRecord, diff_graph_snapshots,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CancellationToken, Config, GraphQueryFilter,
    export::filter_snapshot,
    policy::{
        PolicyAnnotation, PolicyAnnotationLevel, PolicyEntity, PolicyEvidenceSpan, PolicyPathStep,
        PolicyResultSummary, PolicySelectorKind, PolicySeverity, PublicApiChangeKind,
        policy_annotations,
    },
    policy_engine::evaluate_policy_diff,
};

use crate::service::{
    DepgraphService, DepgraphServiceError, DepgraphServiceResult, RepositoryFileError,
    SnapshotLocator,
};

pub const SNAPSHOT_DIFF_SERVICE_SCHEMA_VERSION: &str = "depgraph-snapshot-diff-service-v1";
pub const POLICY_EVALUATION_SERVICE_SCHEMA_VERSION: &str = "depgraph-policy-evaluation-service-v1";
pub const GRAPH_EXPORT_SERVICE_SCHEMA_VERSION: &str = "depgraph-graph-export-service-v1";
pub const DEFAULT_GRAPH_EXPORT_MAX_NODES: usize = 1_000;
pub const DEFAULT_GRAPH_EXPORT_MAX_EDGES: usize = 5_000;
pub const MAX_GRAPH_EXPORT_NODES: usize = 50_000;
pub const MAX_GRAPH_EXPORT_EDGES: usize = 100_000;
pub const MAX_SHARED_ARTIFACT_ITEMS: usize = 50_000;
pub const MAX_SHARED_ARTIFACT_WORK_ITEMS: usize = 1_000_000;
const GRAPH_EXPORT_ENVELOPE_RESERVE_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffFilters {
    kind: Vec<String>,
    profile: Vec<String>,
    phase: Vec<String>,
    status: Vec<String>,
}

impl SnapshotDiffFilters {
    pub fn try_new(
        kind: Vec<String>,
        profile: Vec<String>,
        phase: Vec<String>,
        status: Vec<String>,
    ) -> DepgraphServiceResult<Self> {
        Ok(Self {
            kind: normalize_filter(kind)?,
            profile: normalize_filter(profile)?,
            phase: normalize_filter(phase)?,
            status: normalize_filter(status)?,
        })
    }

    #[must_use]
    pub fn kinds(&self) -> &[String] {
        &self.kind
    }

    #[must_use]
    pub fn profiles(&self) -> &[String] {
        &self.profile
    }

    #[must_use]
    pub fn phases(&self) -> &[String] {
        &self.phase
    }

    #[must_use]
    pub fn statuses(&self) -> &[String] {
        &self.status
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kind.is_empty()
            && self.profile.is_empty()
            && self.phase.is_empty()
            && self.status.is_empty()
    }

    fn apply(&self, diff: GraphSnapshotDiff) -> GraphSnapshotDiff {
        if self.is_empty() {
            return diff;
        }
        let GraphSnapshotDiff {
            schema_version,
            from_snapshot_id,
            to_snapshot_id,
            nodes,
            sites,
            edges,
            evidence,
            profiles,
            coverage: _,
            renames,
            rename_candidates,
        } = diff;
        let nodes = filter_records(nodes, |record| self.matches_node(record));
        let sites = filter_records(sites, |record| self.matches_site(record));
        let edges = filter_records(edges, |record| self.matches_edge(record));
        let profiles = filter_records(profiles, |record| self.matches_profile(record));
        let renames = renames
            .into_iter()
            .filter(|rename| self.matches_rename(rename))
            .collect::<Vec<_>>();
        let rename_candidates = rename_candidates
            .into_iter()
            .filter(|rename| self.matches_rename(rename))
            .collect::<Vec<_>>();
        let retained =
            retained_evidence_owners(&nodes, &sites, &edges, &renames, &rename_candidates);
        let evidence = filter_records(evidence, |record| {
            retained.contains(&(record.owner_type.clone(), record.owner_id.clone()))
        });
        GraphSnapshotDiff {
            schema_version,
            from_snapshot_id,
            to_snapshot_id,
            nodes,
            sites,
            edges,
            evidence,
            profiles,
            coverage: None,
            renames,
            rename_candidates,
        }
    }

    fn matches_node(&self, value: &NodeRecord) -> bool {
        dimension_matches(&self.kind, Some(&value.kind))
            && dimension_matches(&self.profile, None)
            && dimension_matches(&self.phase, None)
            && dimension_matches(&self.status, None)
    }

    fn matches_site(&self, value: &SiteRecord) -> bool {
        dimension_matches(&self.kind, Some(&value.kind))
            && dimension_matches(&self.profile, Some(&value.profile_id))
            && dimension_matches(&self.phase, None)
            && dimension_matches(&self.status, Some(&value.resolution_status))
    }

    fn matches_edge(&self, value: &EdgeRecord) -> bool {
        dimension_matches(&self.kind, Some(&value.kind))
            && dimension_matches(&self.profile, Some(&value.profile_id))
            && dimension_matches(&self.phase, Some(&value.phase))
            && dimension_matches(&self.status, Some(&value.resolution_status))
    }

    fn matches_profile(&self, value: &ProfileRecord) -> bool {
        dimension_matches(&self.kind, None)
            && dimension_matches(&self.profile, Some(&value.id))
            && dimension_matches(&self.phase, None)
            && dimension_matches(&self.status, None)
    }

    fn matches_rename(&self, value: &NodeRename) -> bool {
        dimension_matches(&self.kind, Some(&value.kind))
            && dimension_matches(&self.profile, None)
            && dimension_matches(&self.phase, None)
            && dimension_matches(&self.status, None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDiffRequest {
    from: SnapshotLocator,
    to: SnapshotLocator,
    filters: SnapshotDiffFilters,
}

impl SnapshotDiffRequest {
    #[must_use]
    pub const fn new(
        from: SnapshotLocator,
        to: SnapshotLocator,
        filters: SnapshotDiffFilters,
    ) -> Self {
        Self { from, to, filters }
    }

    #[must_use]
    pub const fn from(&self) -> &SnapshotLocator {
        &self.from
    }

    #[must_use]
    pub const fn to(&self) -> &SnapshotLocator {
        &self.to
    }

    #[must_use]
    pub const fn filters(&self) -> &SnapshotDiffFilters {
        &self.filters
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordChangeSummary {
    pub added: u64,
    pub removed: u64,
    pub changed: u64,
}

impl RecordChangeSummary {
    fn from_diff<T>(records: &RecordDiff<T>) -> Self {
        Self {
            added: records.added.len() as u64,
            removed: records.removed.len() as u64,
            changed: records.changed.len() as u64,
        }
    }

    const fn total(self) -> u64 {
        self.added + self.removed + self.changed
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenameSummary {
    pub confirmed: u64,
    pub candidates: u64,
    pub exact: u64,
    pub high: u64,
    pub medium: u64,
    pub ambiguous: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffSummary {
    pub empty: bool,
    pub total_changes: u64,
    pub nodes: RecordChangeSummary,
    pub sites: RecordChangeSummary,
    pub edges: RecordChangeSummary,
    pub evidence: RecordChangeSummary,
    pub profiles: RecordChangeSummary,
    pub coverage_changed: bool,
    pub renames: RenameSummary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedRecordDiff<T> {
    pub added: Vec<T>,
    pub removed: Vec<T>,
    pub changed: Vec<ClosedChangedRecord<T>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedChangedRecord<T> {
    pub id: String,
    pub changed_fields: Vec<String>,
    pub before: T,
    pub after: T,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffNode {
    pub id: String,
    pub kind: String,
    pub locator: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffSite {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub specifier: Option<String>,
    pub profile_id: String,
    pub resolution_status: String,
    pub precision: String,
    pub target_ids: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffEdge {
    pub id: String,
    pub site_id: Option<String>,
    pub source: String,
    pub target: String,
    pub kind: String,
    pub phase: String,
    pub environment: String,
    pub profile_id: String,
    pub resolution_status: String,
    pub precision: String,
    pub generated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffEvidence {
    pub owner_type: String,
    pub owner_id: String,
    pub ordinal: i64,
    pub kind: String,
    pub extractor: String,
    pub extractor_version: String,
    pub path: String,
    pub start_line: u64,
    pub start_column: u64,
    pub end_line: u64,
    pub end_column: u64,
}

impl SnapshotDiffEvidence {
    #[must_use]
    pub fn id(&self) -> String {
        format!("{}:{}#{}", self.owner_type, self.owner_id, self.ordinal)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffProfile {
    pub id: String,
    pub language: String,
    pub target: Option<String>,
    pub features: Vec<String>,
    pub source_revision: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffCoverage {
    pub profiles: u64,
    pub files_discovered: u64,
    pub files_analyzed: u64,
    pub files_skipped: u64,
    pub dependency_sites: u64,
    pub resolved: u64,
    pub candidates: u64,
    pub external: u64,
    pub unresolved: u64,
    pub unsupported_syntax: u64,
    pub project_code_executed: bool,
    pub completeness: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffRename {
    pub kind: String,
    pub old_id: String,
    pub new_id: String,
    pub confidence: RenameConfidence,
    pub changed_fields: Vec<String>,
    pub before: SnapshotDiffNode,
    pub after: SnapshotDiffNode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDiffResult {
    pub schema_version: String,
    pub from_snapshot_id: String,
    pub to_snapshot_id: String,
    pub filters: SnapshotDiffFilters,
    pub summary: SnapshotDiffSummary,
    pub nodes: ClosedRecordDiff<SnapshotDiffNode>,
    pub sites: ClosedRecordDiff<SnapshotDiffSite>,
    pub edges: ClosedRecordDiff<SnapshotDiffEdge>,
    pub evidence: ClosedRecordDiff<SnapshotDiffEvidence>,
    pub profiles: ClosedRecordDiff<SnapshotDiffProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<ClosedChangedRecord<SnapshotDiffCoverage>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renames: Vec<SnapshotDiffRename>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rename_candidates: Vec<SnapshotDiffRename>,
    pub collection_digest: String,
}

impl SnapshotDiffResult {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.summary.empty
    }

    #[must_use]
    pub fn item_count(&self) -> usize {
        diff_item_count(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEvaluateRequest {
    from: SnapshotLocator,
    to: SnapshotLocator,
}

impl PolicyEvaluateRequest {
    #[must_use]
    pub const fn new(from: SnapshotLocator, to: SnapshotLocator) -> Self {
        Self { from, to }
    }

    #[must_use]
    pub const fn from(&self) -> &SnapshotLocator {
        &self.from
    }

    #[must_use]
    pub const fn to(&self) -> &SnapshotLocator {
        &self.to
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicyApiChange {
    pub id: String,
    pub rule_id: String,
    pub kind: PublicApiChangeKind,
    pub breaking: bool,
    pub changed_fields: Vec<String>,
    pub before: Option<PolicyEntity>,
    pub after: Option<PolicyEntity>,
    pub profile_id: Option<String>,
    pub evidence: Vec<PolicyEvidenceSpan>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicySuppression {
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicyViolation {
    pub id: String,
    pub rule_id: String,
    pub severity: PolicySeverity,
    pub message: String,
    pub source: PolicyEntity,
    pub target: PolicyEntity,
    pub dependency_path: Vec<PolicyPathStep>,
    pub profile_id: Option<String>,
    pub evidence: Vec<PolicyEvidenceSpan>,
    pub change_id: Option<String>,
    pub suppression: Option<ServicePolicySuppression>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicyAnnotation {
    pub violation_id: String,
    pub rule_id: String,
    pub level: PolicyAnnotationLevel,
    pub path: String,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub title: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicyResult {
    pub schema_version: String,
    pub result_id: String,
    pub policy_config_digest: String,
    pub snapshot_id: String,
    pub api_changes: Vec<ServicePolicyApiChange>,
    pub violations: Vec<ServicePolicyViolation>,
    pub summary: PolicyResultSummary,
    pub exit_code: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluationResult {
    pub from_snapshot_id: String,
    pub to_snapshot_id: String,
    pub result: ServicePolicyResult,
    pub annotations: Vec<ServicePolicyAnnotation>,
    pub collection_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExportFormat {
    Json,
    Dot,
    Mermaid,
    Graphml,
}

impl GraphExportFormat {
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Dot => "text/vnd.graphviz",
            Self::Mermaid => "text/vnd.mermaid",
            Self::Graphml => "application/graphml+xml",
        }
    }
}

#[derive(Clone, Debug)]
pub struct GraphExportRequest {
    snapshot: SnapshotLocator,
    format: GraphExportFormat,
    selector: Option<String>,
    filter: GraphQueryFilter,
    max_nodes: usize,
    max_edges: usize,
}

impl GraphExportRequest {
    pub fn try_new(
        snapshot: SnapshotLocator,
        format: GraphExportFormat,
        selector: Option<String>,
        filter: GraphQueryFilter,
        max_nodes: usize,
        max_edges: usize,
    ) -> DepgraphServiceResult<Self> {
        if !(1..=MAX_GRAPH_EXPORT_NODES).contains(&max_nodes)
            || !(1..=MAX_GRAPH_EXPORT_EDGES).contains(&max_edges)
            || selector.as_ref().is_some_and(|value| {
                value.trim().is_empty()
                    || value.len() > 1_024
                    || value.chars().any(char::is_control)
            })
        {
            return Err(DepgraphServiceError::InvalidInput);
        }
        validate_graph_filter(&filter)?;
        Ok(Self {
            snapshot,
            format,
            selector,
            filter,
            max_nodes,
            max_edges,
        })
    }

    #[must_use]
    pub const fn snapshot(&self) -> &SnapshotLocator {
        &self.snapshot
    }

    #[must_use]
    pub const fn format(&self) -> GraphExportFormat {
        self.format
    }

    #[must_use]
    pub fn selector(&self) -> Option<&str> {
        self.selector.as_deref()
    }

    #[must_use]
    pub const fn filter(&self) -> &GraphQueryFilter {
        &self.filter
    }

    #[must_use]
    pub const fn max_nodes(&self) -> usize {
        self.max_nodes
    }

    #[must_use]
    pub const fn max_edges(&self) -> usize {
        self.max_edges
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphExportResult {
    pub schema_version: String,
    pub snapshot_id: String,
    pub format: GraphExportFormat,
    pub media_type: String,
    pub content: String,
    pub content_sha256: String,
    pub output_bytes: u64,
    pub node_count: u64,
    pub edge_count: u64,
}

impl DepgraphService {
    pub fn snapshot_diff(
        &self,
        request: &SnapshotDiffRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<SnapshotDiffResult> {
        let (from_id, from, to_id, to) =
            self.load_snapshot_pair(request.from(), request.to(), cancellation)?;
        preflight_graph_work(&from, &to, 1, cancellation)?;
        check_cancelled(cancellation)?;
        let raw = diff_graph_snapshots(&from_id, &to_id, from, to)
            .map_err(|source| cancelled_or_store(source, cancellation))?;
        let filtered = request.filters().apply(raw);
        if graph_snapshot_diff_item_count(&filtered) > MAX_SHARED_ARTIFACT_ITEMS {
            return Err(cancelled_or(
                DepgraphServiceError::ResourceExhausted,
                cancellation,
            ));
        }
        let mut result = project_snapshot_diff(filtered, request.filters().clone(), cancellation)?;
        if result.item_count() > MAX_SHARED_ARTIFACT_ITEMS {
            return Err(cancelled_or(
                DepgraphServiceError::ResourceExhausted,
                cancellation,
            ));
        }
        result.collection_digest = stable_id_from_value(
            "snapshot-diff-collection",
            &serde_json::to_value(&result).map_err(|_| DepgraphServiceError::Internal)?,
        );
        enforce_output_bound(self, &result, cancellation)?;
        Ok(result)
    }

    pub fn policy_evaluate(
        &self,
        request: &PolicyEvaluateRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<PolicyEvaluationResult> {
        let (from_id, from, to_id, to) =
            self.load_snapshot_pair(request.from(), request.to(), cancellation)?;
        let policy = self.read_policy_config(cancellation)?;
        let policy_value = policy
            .normalized_identity()
            .map_err(|_| DepgraphServiceError::Internal)?;
        let policy_config_digest = stable_id_from_value("policy-config", &policy_value);
        let rule_factor = policy.rules.len().saturating_add(1);
        preflight_graph_work(&from, &to, rule_factor, cancellation)?;
        check_cancelled(cancellation)?;
        let evaluated = evaluate_policy_diff(&from_id, &from, &to_id, &to, &policy)
            .map_err(|source| cancelled_or_policy(source, cancellation))?;
        check_cancelled(cancellation)?;
        if evaluated
            .api_changes
            .len()
            .saturating_add(evaluated.violations.len())
            > MAX_SHARED_ARTIFACT_ITEMS
        {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        let annotations = policy_annotations(&evaluated)
            .map_err(|source| cancelled_or_policy(source, cancellation))?;
        let mut api_changes = Vec::with_capacity(evaluated.api_changes.len());
        for (index, change) in evaluated.api_changes.iter().enumerate() {
            if index.is_multiple_of(128) {
                check_cancelled(cancellation)?;
            }
            api_changes.push(ServicePolicyApiChange {
                id: change.id.clone(),
                rule_id: change.rule_id.clone(),
                kind: change.kind,
                breaking: change.breaking,
                changed_fields: change.changed_fields.clone(),
                before: change.before.clone(),
                after: change.after.clone(),
                profile_id: change.profile_id.clone(),
                evidence: change.evidence.clone(),
            });
        }
        let mut violations = Vec::with_capacity(evaluated.violations.len());
        for (index, violation) in evaluated.violations.iter().enumerate() {
            if index.is_multiple_of(128) {
                check_cancelled(cancellation)?;
            }
            violations.push(ServicePolicyViolation {
                id: violation.id.clone(),
                rule_id: violation.rule_id.clone(),
                severity: violation.severity,
                message: violation.message.clone(),
                source: violation.source.clone(),
                target: violation.target.clone(),
                dependency_path: violation.dependency_path.clone(),
                profile_id: violation.profile_id.clone(),
                evidence: violation.evidence.clone(),
                change_id: violation.change_id.clone(),
                suppression: violation.suppression.as_ref().map(|suppression| {
                    ServicePolicySuppression {
                        id: suppression.id.clone(),
                    }
                }),
            });
        }
        let mut projected_annotations = Vec::with_capacity(annotations.len());
        for (index, annotation) in annotations.iter().enumerate() {
            if index.is_multiple_of(128) {
                check_cancelled(cancellation)?;
            }
            projected_annotations.push(ServicePolicyAnnotation::from(annotation));
        }
        if api_changes
            .len()
            .saturating_add(violations.len())
            .saturating_add(projected_annotations.len())
            > MAX_SHARED_ARTIFACT_ITEMS
        {
            return Err(cancelled_or(
                DepgraphServiceError::ResourceExhausted,
                cancellation,
            ));
        }
        let mut result = ServicePolicyResult {
            schema_version: POLICY_EVALUATION_SERVICE_SCHEMA_VERSION.to_owned(),
            result_id: String::new(),
            policy_config_digest,
            snapshot_id: evaluated.snapshot_id,
            api_changes,
            violations,
            summary: evaluated.summary,
            exit_code: evaluated.exit_code,
        };
        result.result_id = stable_id_from_value(
            "policy-evaluation",
            &serde_json::json!({
                "from_snapshot_id": from_id,
                "to_snapshot_id": to_id,
                "policy_config_digest": result.policy_config_digest,
                "api_changes": result.api_changes,
                "violations": result.violations,
                "summary": result.summary,
            }),
        );
        let collection_digest = stable_id_from_value(
            "policy-evaluation-collection",
            &serde_json::json!({
                "result_id": result.result_id,
                "api_changes": result.api_changes,
                "violations": result.violations,
                "annotations": projected_annotations,
            }),
        );
        let response = PolicyEvaluationResult {
            from_snapshot_id: from_id,
            to_snapshot_id: to_id,
            result,
            annotations: projected_annotations,
            collection_digest,
        };
        enforce_output_bound(self, &response, cancellation)?;
        Ok(response)
    }

    pub fn graph_export(
        &self,
        request: &GraphExportRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<GraphExportResult> {
        check_cancelled(cancellation)?;
        let mut snapshot_request =
            self.start_snapshot_request_at_cancellable(request.snapshot(), cancellation)?;
        let snapshot_id = snapshot_request.snapshot_id().as_str().to_owned();
        let snapshot =
            crate::service_graph::load_pinned_snapshot(&mut snapshot_request, cancellation)?;
        let filtered = filter_snapshot(&snapshot, request.filter());
        let mut selected = select_export_graph(filtered, request, cancellation)?;
        if selected.nodes.len() > request.max_nodes() || selected.edges.len() > request.max_edges()
        {
            return Err(cancelled_or(
                DepgraphServiceError::ResourceExhausted,
                cancellation,
            ));
        }
        canonicalize_export_graph(&mut selected);
        let maximum = self.config().limits().max_output_bytes();
        let mut writer = BoundedOutput::new(maximum, cancellation.clone());
        let rendered = write_agent_safe_export(&selected, request.format(), &mut writer);
        if rendered.is_err() {
            if cancellation.is_cancelled() {
                return Err(DepgraphServiceError::Cancelled);
            }
            if writer.exceeded {
                return Err(DepgraphServiceError::InlineExportTooLarge { maximum });
            }
            return Err(DepgraphServiceError::Internal);
        }
        check_cancelled(cancellation)?;
        let output = writer.into_bytes();
        let content = String::from_utf8(output).map_err(|_| DepgraphServiceError::Integrity)?;
        let content_sha256 = hex::encode(Sha256::digest(content.as_bytes()));
        let result = GraphExportResult {
            schema_version: GRAPH_EXPORT_SERVICE_SCHEMA_VERSION.to_owned(),
            snapshot_id,
            format: request.format(),
            media_type: request.format().media_type().to_owned(),
            output_bytes: content.len() as u64,
            node_count: selected.nodes.len() as u64,
            edge_count: selected.edges.len() as u64,
            content,
            content_sha256,
        };
        enforce_graph_export_output_bound(self, &result, cancellation)?;
        Ok(result)
    }

    pub(crate) fn graph_export_raw_compatible(
        &self,
        request: &GraphExportRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<GraphExportResult> {
        check_cancelled(cancellation)?;
        let mut snapshot_request =
            self.start_snapshot_request_at_cancellable(request.snapshot(), cancellation)?;
        let snapshot_id = snapshot_request.snapshot_id().as_str().to_owned();
        let snapshot =
            crate::service_graph::load_pinned_snapshot(&mut snapshot_request, cancellation)?;
        let filtered = filter_snapshot(&snapshot, request.filter());
        let selected = select_export_graph(filtered, request, cancellation)?;
        if selected.nodes.len() > request.max_nodes() || selected.edges.len() > request.max_edges()
        {
            return Err(cancelled_or(
                DepgraphServiceError::ResourceExhausted,
                cancellation,
            ));
        }
        let format = match request.format() {
            GraphExportFormat::Json => crate::ExportFormat::Json,
            GraphExportFormat::Dot => crate::ExportFormat::Dot,
            GraphExportFormat::Mermaid => crate::ExportFormat::Mermaid,
            GraphExportFormat::Graphml => crate::ExportFormat::Graphml,
        };
        let content = crate::export_filtered(&selected, format, &GraphQueryFilter::default())
            .map_err(|_| DepgraphServiceError::Internal)?;
        check_cancelled(cancellation)?;
        let maximum = self.config().limits().max_output_bytes();
        if content.len() > maximum {
            return Err(DepgraphServiceError::InlineExportTooLarge { maximum });
        }
        Ok(GraphExportResult {
            schema_version: GRAPH_EXPORT_SERVICE_SCHEMA_VERSION.to_owned(),
            snapshot_id,
            format: request.format(),
            media_type: request.format().media_type().to_owned(),
            output_bytes: content.len() as u64,
            node_count: selected.nodes.len() as u64,
            edge_count: selected.edges.len() as u64,
            content_sha256: hex::encode(Sha256::digest(content.as_bytes())),
            content,
        })
    }

    fn load_snapshot_pair(
        &self,
        from: &SnapshotLocator,
        to: &SnapshotLocator,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<(String, GraphSnapshot, String, GraphSnapshot)> {
        check_cancelled(cancellation)?;
        let mut read_store = self.read_store_factory().open()?;
        let from = from.clone();
        let to = to.clone();
        let cancellation_check = cancellation.clone();
        let loaded = read_store.store().interruptible_read(
            move || cancellation_check.is_cancelled(),
            move |store| {
                let Some(from_id) = resolve_locator(store, &from)? else {
                    return Ok(None);
                };
                let Some(to_id) = resolve_locator(store, &to)? else {
                    return Ok(None);
                };
                let from_snapshot = store.load_completed_snapshot(&from_id)?;
                let to_snapshot = if from_id == to_id {
                    from_snapshot.clone()
                } else {
                    store.load_completed_snapshot(&to_id)?
                };
                Ok(Some((from_id, from_snapshot, to_id, to_snapshot)))
            },
        );
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        loaded
            .map_err(DepgraphServiceError::store_operation)?
            .ok_or(DepgraphServiceError::NotFound)
    }

    fn read_policy_config(
        &self,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<crate::policy::PolicyConfig> {
        check_cancelled(cancellation)?;
        let mut input = match self.open_repository_input(crate::config::CONFIG_FILE) {
            Ok(input) => input,
            Err(DepgraphServiceError::RepositoryFile {
                reason: RepositoryFileError::NotFound,
            }) => return Ok(crate::policy::PolicyConfig::default()),
            Err(error) => return Err(error),
        };
        let maximum = self.config().limits().max_inline_input_bytes();
        let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
        Read::by_ref(&mut input)
            .take((maximum as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| DepgraphServiceError::RepositoryFile {
                reason: RepositoryFileError::Unavailable {
                    source: io::Error::other("repository config read failed"),
                },
            })?;
        if bytes.len() > maximum {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        check_cancelled(cancellation)?;
        let raw = std::str::from_utf8(&bytes).map_err(|_| DepgraphServiceError::PolicyInput)?;
        let config = Config::parse(raw).map_err(|_| DepgraphServiceError::PolicyInput)?;
        Ok(config.policy)
    }
}

impl From<&PolicyAnnotation> for ServicePolicyAnnotation {
    fn from(annotation: &PolicyAnnotation) -> Self {
        Self {
            violation_id: annotation.violation_id.clone(),
            rule_id: annotation.rule_id.clone(),
            level: annotation.level,
            path: annotation.path.clone(),
            start_line: annotation.start_line,
            start_column: annotation.start_column,
            end_line: annotation.end_line,
            end_column: annotation.end_column,
            title: annotation.title.clone(),
            message: annotation.message.clone(),
        }
    }
}

fn normalize_filter(values: Vec<String>) -> DepgraphServiceResult<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err(DepgraphServiceError::InvalidInput);
        }
        normalized.insert(value.to_owned());
        if normalized.len() > 1_024 {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
    }
    Ok(normalized.into_iter().collect())
}

fn dimension_matches(filter: &[String], value: Option<&String>) -> bool {
    filter.is_empty()
        || value.is_some_and(|value| filter.binary_search_by(|item| item.cmp(value)).is_ok())
}

fn filter_records<T>(mut records: RecordDiff<T>, matches: impl Fn(&T) -> bool) -> RecordDiff<T> {
    records.added.retain(&matches);
    records.removed.retain(&matches);
    records
        .changed
        .retain(|record| matches(&record.before) || matches(&record.after));
    records
}

fn retained_evidence_owners(
    nodes: &RecordDiff<NodeRecord>,
    sites: &RecordDiff<SiteRecord>,
    edges: &RecordDiff<EdgeRecord>,
    renames: &[NodeRename],
    candidates: &[NodeRename],
) -> BTreeSet<(String, String)> {
    let mut owners = BTreeSet::new();
    add_owners(&mut owners, "node", nodes, |record| &record.id);
    add_owners(&mut owners, "site", sites, |record| &record.id);
    add_owners(&mut owners, "edge", edges, |record| &record.id);
    for rename in renames.iter().chain(candidates) {
        owners.insert(("node".to_owned(), rename.old_id.clone()));
        owners.insert(("node".to_owned(), rename.new_id.clone()));
    }
    owners
}

fn add_owners<T>(
    owners: &mut BTreeSet<(String, String)>,
    owner_type: &str,
    records: &RecordDiff<T>,
    id: impl Fn(&T) -> &String,
) {
    for record in records.added.iter().chain(&records.removed) {
        owners.insert((owner_type.to_owned(), id(record).clone()));
    }
    for record in &records.changed {
        owners.insert((owner_type.to_owned(), id(&record.before).clone()));
        owners.insert((owner_type.to_owned(), id(&record.after).clone()));
    }
}

fn project_snapshot_diff(
    diff: GraphSnapshotDiff,
    filters: SnapshotDiffFilters,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<SnapshotDiffResult> {
    let summary = snapshot_diff_summary(&diff);
    let nodes = project_records(diff.nodes, SnapshotDiffNode::from, cancellation)?;
    let sites = project_records(diff.sites, SnapshotDiffSite::from, cancellation)?;
    let edges = project_records(diff.edges, SnapshotDiffEdge::from, cancellation)?;
    let evidence = project_records(diff.evidence, SnapshotDiffEvidence::from, cancellation)?;
    let profiles = project_records(diff.profiles, SnapshotDiffProfile::from, cancellation)?;
    let coverage = diff.coverage.map(|changed| ClosedChangedRecord {
        id: changed.id,
        changed_fields: changed.changed_fields,
        before: SnapshotDiffCoverage::from(changed.before),
        after: SnapshotDiffCoverage::from(changed.after),
    });
    let renames = project_renames(diff.renames, cancellation)?;
    let rename_candidates = project_renames(diff.rename_candidates, cancellation)?;
    Ok(SnapshotDiffResult {
        schema_version: SNAPSHOT_DIFF_SERVICE_SCHEMA_VERSION.to_owned(),
        from_snapshot_id: diff.from_snapshot_id,
        to_snapshot_id: diff.to_snapshot_id,
        filters,
        summary,
        nodes,
        sites,
        edges,
        evidence,
        profiles,
        coverage,
        renames,
        rename_candidates,
        collection_digest: String::new(),
    })
}

fn project_records<T, U>(
    records: RecordDiff<T>,
    project: impl Fn(T) -> U + Copy,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<ClosedRecordDiff<U>> {
    let mut work = 0_usize;
    let mut map = |record| {
        work = work.saturating_add(1);
        if work > MAX_SHARED_ARTIFACT_WORK_ITEMS || cancellation.is_cancelled() {
            return Err(cancelled_or(
                DepgraphServiceError::ResourceExhausted,
                cancellation,
            ));
        }
        Ok(project(record))
    };
    let added = records
        .added
        .into_iter()
        .map(&mut map)
        .collect::<DepgraphServiceResult<Vec<_>>>()?;
    let removed = records
        .removed
        .into_iter()
        .map(&mut map)
        .collect::<DepgraphServiceResult<Vec<_>>>()?;
    let mut changed = Vec::with_capacity(records.changed.len());
    for record in records.changed {
        check_cancelled(cancellation)?;
        changed.push(ClosedChangedRecord {
            id: record.id,
            changed_fields: record.changed_fields,
            before: map(record.before)?,
            after: map(record.after)?,
        });
    }
    Ok(ClosedRecordDiff {
        added,
        removed,
        changed,
    })
}

fn project_renames(
    renames: Vec<NodeRename>,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<Vec<SnapshotDiffRename>> {
    let mut projected = Vec::with_capacity(renames.len());
    for rename in renames {
        check_cancelled(cancellation)?;
        projected.push(SnapshotDiffRename {
            kind: rename.kind,
            old_id: rename.old_id,
            new_id: rename.new_id,
            confidence: rename.confidence,
            changed_fields: rename.changed_fields,
            before: SnapshotDiffNode::from(rename.before),
            after: SnapshotDiffNode::from(rename.after),
        });
    }
    Ok(projected)
}

fn snapshot_diff_summary(diff: &GraphSnapshotDiff) -> SnapshotDiffSummary {
    let nodes = RecordChangeSummary::from_diff(&diff.nodes);
    let sites = RecordChangeSummary::from_diff(&diff.sites);
    let edges = RecordChangeSummary::from_diff(&diff.edges);
    let evidence = RecordChangeSummary::from_diff(&diff.evidence);
    let profiles = RecordChangeSummary::from_diff(&diff.profiles);
    let mut renames = RenameSummary {
        confirmed: diff.renames.len() as u64,
        candidates: diff.rename_candidates.len() as u64,
        ..RenameSummary::default()
    };
    for rename in diff.renames.iter().chain(&diff.rename_candidates) {
        match rename.confidence {
            RenameConfidence::Exact => renames.exact += 1,
            RenameConfidence::High => renames.high += 1,
            RenameConfidence::Medium => renames.medium += 1,
            RenameConfidence::Ambiguous => renames.ambiguous += 1,
        }
    }
    SnapshotDiffSummary {
        empty: diff.is_empty(),
        total_changes: nodes.total()
            + sites.total()
            + edges.total()
            + evidence.total()
            + profiles.total()
            + u64::from(diff.coverage.is_some())
            + renames.confirmed,
        nodes,
        sites,
        edges,
        evidence,
        profiles,
        coverage_changed: diff.coverage.is_some(),
        renames,
    }
}

fn diff_item_count(result: &SnapshotDiffResult) -> usize {
    fn records<T>(records: &ClosedRecordDiff<T>) -> usize {
        records
            .added
            .len()
            .saturating_add(records.removed.len())
            .saturating_add(records.changed.len())
    }
    records(&result.nodes)
        .saturating_add(records(&result.sites))
        .saturating_add(records(&result.edges))
        .saturating_add(records(&result.evidence))
        .saturating_add(records(&result.profiles))
        .saturating_add(usize::from(result.coverage.is_some()))
        .saturating_add(result.renames.len())
        .saturating_add(result.rename_candidates.len())
}

fn graph_snapshot_diff_item_count(diff: &GraphSnapshotDiff) -> usize {
    fn records<T>(records: &RecordDiff<T>) -> usize {
        records
            .added
            .len()
            .saturating_add(records.removed.len())
            .saturating_add(records.changed.len())
    }
    records(&diff.nodes)
        .saturating_add(records(&diff.sites))
        .saturating_add(records(&diff.edges))
        .saturating_add(records(&diff.evidence))
        .saturating_add(records(&diff.profiles))
        .saturating_add(usize::from(diff.coverage.is_some()))
        .saturating_add(diff.renames.len())
        .saturating_add(diff.rename_candidates.len())
}

impl From<NodeRecord> for SnapshotDiffNode {
    fn from(value: NodeRecord) -> Self {
        Self {
            id: value.id,
            kind: value.kind,
            locator: value.locator,
            display_name: value.display_name,
        }
    }
}

impl From<SiteRecord> for SnapshotDiffSite {
    fn from(value: SiteRecord) -> Self {
        Self {
            id: value.id,
            source: value.source,
            kind: value.kind,
            specifier: value.specifier,
            profile_id: value.profile_id,
            resolution_status: value.resolution_status,
            precision: value.precision,
            target_ids: value.target_ids,
            reason: value.reason,
        }
    }
}

impl From<EdgeRecord> for SnapshotDiffEdge {
    fn from(value: EdgeRecord) -> Self {
        Self {
            id: value.id,
            site_id: value.site_id,
            source: value.source,
            target: value.target,
            kind: value.kind,
            phase: value.phase,
            environment: value.environment,
            profile_id: value.profile_id,
            resolution_status: value.resolution_status,
            precision: value.precision,
            generated: value.generated,
        }
    }
}

impl From<EvidenceRecord> for SnapshotDiffEvidence {
    fn from(value: EvidenceRecord) -> Self {
        Self {
            owner_type: value.owner_type,
            owner_id: value.owner_id,
            ordinal: value.ordinal,
            kind: value.kind,
            extractor: value.extractor,
            extractor_version: value.extractor_version,
            path: value.path,
            start_line: value.start_line,
            start_column: value.start_column,
            end_line: value.end_line,
            end_column: value.end_column,
        }
    }
}

impl From<ProfileRecord> for SnapshotDiffProfile {
    fn from(value: ProfileRecord) -> Self {
        Self {
            id: value.id,
            language: value.language,
            target: value.target,
            features: value.features,
            source_revision: value.source_revision,
        }
    }
}

impl From<CoverageRecord> for SnapshotDiffCoverage {
    fn from(value: CoverageRecord) -> Self {
        Self {
            profiles: value.profiles,
            files_discovered: value.files_discovered,
            files_analyzed: value.files_analyzed,
            files_skipped: value.files_skipped,
            dependency_sites: value.dependency_sites,
            resolved: value.resolved,
            candidates: value.candidates,
            external: value.external,
            unresolved: value.unresolved,
            unsupported_syntax: value.unsupported_syntax,
            project_code_executed: value.project_code_executed,
            completeness: value.completeness,
            reasons: value.reasons,
        }
    }
}

fn preflight_graph_work(
    from: &GraphSnapshot,
    to: &GraphSnapshot,
    factor: usize,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<()> {
    check_cancelled(cancellation)?;
    let count = graph_record_count(from)
        .checked_add(graph_record_count(to))
        .and_then(|count| count.checked_mul(factor))
        .ok_or(DepgraphServiceError::ResourceExhausted)?;
    if count > MAX_SHARED_ARTIFACT_WORK_ITEMS {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    Ok(())
}

fn graph_record_count(snapshot: &GraphSnapshot) -> usize {
    snapshot
        .nodes
        .len()
        .saturating_add(snapshot.sites.len())
        .saturating_add(snapshot.edges.len())
        .saturating_add(snapshot.evidence.len())
        .saturating_add(snapshot.profiles.len())
}

fn resolve_locator(
    store: &depgraph_store::Store,
    locator: &SnapshotLocator,
) -> anyhow::Result<Option<String>> {
    let id = match locator {
        SnapshotLocator::Current => store.current_snapshot_id()?,
        SnapshotLocator::Name(name) => store.snapshot_id_for_name(name)?,
        SnapshotLocator::StableId(id) => store.completed_snapshot(id)?.map(|record| record.id),
    };
    let Some(id) = id else {
        return Ok(None);
    };
    let record = store
        .completed_snapshot(&id)?
        .ok_or_else(|| anyhow::anyhow!("completed snapshot was not found"))?;
    anyhow::ensure!(record.status == "completed", "snapshot is not completed");
    Ok(Some(id))
}

fn canonicalize_export_graph(snapshot: &mut GraphSnapshot) {
    snapshot.nodes.sort_by(|left, right| left.id.cmp(&right.id));
    snapshot.sites.sort_by(|left, right| left.id.cmp(&right.id));
    snapshot.edges.sort_by(|left, right| left.id.cmp(&right.id));
    snapshot
        .profiles
        .sort_by(|left, right| left.id.cmp(&right.id));
    snapshot.evidence.sort_by(|left, right| {
        (
            &left.owner_type,
            &left.owner_id,
            left.ordinal,
            &left.kind,
            &left.extractor,
            &left.path,
        )
            .cmp(&(
                &right.owner_type,
                &right.owner_id,
                right.ordinal,
                &right.kind,
                &right.extractor,
                &right.path,
            ))
    });
    snapshot
        .diagnostics
        .sort_by(|left, right| (left.ordinal, &left.id).cmp(&(right.ordinal, &right.id)));
    snapshot
        .file_coverage
        .sort_by(|left, right| (&left.adapter, &left.path).cmp(&(&right.adapter, &right.path)));
    depgraph_store::refresh_profile_matrix_view(snapshot);
}

fn validate_graph_filter(filter: &GraphQueryFilter) -> DepgraphServiceResult<()> {
    for values in [
        &filter.phases,
        &filter.profiles,
        &filter.sessions,
        &filter.environments,
    ] {
        if values.len() > 1_024
            || values.iter().any(|value| {
                value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control)
            })
            || values.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(DepgraphServiceError::InvalidInput);
        }
    }
    Ok(())
}

fn select_export_graph(
    mut snapshot: GraphSnapshot,
    request: &GraphExportRequest,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<GraphSnapshot> {
    let Some(selector) = request.selector() else {
        return Ok(snapshot);
    };
    let root = crate::query::resolve_selector_bounded_cancellable(
        &snapshot,
        selector,
        MAX_SHARED_ARTIFACT_WORK_ITEMS,
        &mut || cancellation.is_cancelled(),
    )
    .map_err(|_| cancelled_or(DepgraphServiceError::InvalidInput, cancellation))?;
    let mut adjacency = BTreeMap::<String, Vec<String>>::new();
    for (index, edge) in snapshot.edges.iter().enumerate() {
        if index.is_multiple_of(128) {
            check_cancelled(cancellation)?;
        }
        if index.saturating_mul(2) > MAX_SHARED_ARTIFACT_WORK_ITEMS {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        adjacency
            .entry(edge.source.clone())
            .or_default()
            .push(edge.target.clone());
        adjacency
            .entry(edge.target.clone())
            .or_default()
            .push(edge.source.clone());
    }
    for neighbors in adjacency.values_mut() {
        neighbors.sort();
        neighbors.dedup();
    }
    let mut retained = BTreeSet::from([root.id.clone()]);
    let mut queue = VecDeque::from([root.id]);
    let mut work = 0_usize;
    while let Some(node) = queue.pop_front() {
        for next in adjacency.get(&node).into_iter().flatten() {
            work = work.saturating_add(1);
            if work > MAX_SHARED_ARTIFACT_WORK_ITEMS {
                return Err(DepgraphServiceError::ResourceExhausted);
            }
            if work.is_multiple_of(128) {
                check_cancelled(cancellation)?;
            }
            if retained.insert(next.clone()) {
                if retained.len() > request.max_nodes() {
                    return Err(DepgraphServiceError::ResourceExhausted);
                }
                queue.push_back(next.clone());
            }
        }
    }
    snapshot
        .nodes
        .retain(|node| retained.contains(node.id.as_str()));
    snapshot.edges.retain(|edge| {
        retained.contains(edge.source.as_str()) && retained.contains(edge.target.as_str())
    });
    let edge_ids = snapshot
        .edges
        .iter()
        .map(|edge| edge.id.as_str())
        .collect::<BTreeSet<_>>();
    let site_ids = snapshot
        .edges
        .iter()
        .filter_map(|edge| edge.site_id.as_deref())
        .collect::<BTreeSet<_>>();
    snapshot
        .sites
        .retain(|site| site_ids.contains(site.id.as_str()));
    snapshot.evidence.retain(|evidence| {
        (evidence.owner_type == "edge" && edge_ids.contains(evidence.owner_id.as_str()))
            || (evidence.owner_type == "site" && site_ids.contains(evidence.owner_id.as_str()))
    });
    Ok(snapshot)
}

#[derive(Serialize)]
struct AgentSafeJsonExport<'a> {
    schema_version: &'static str,
    nodes: Vec<AgentSafeJsonNode<'a>>,
    edges: Vec<AgentSafeJsonEdge<'a>>,
}

#[derive(Serialize)]
struct AgentSafeJsonNode<'a> {
    id: &'a str,
    kind: &'a str,
    locator: &'a str,
    display_name: &'a str,
}

#[derive(Serialize)]
struct AgentSafeJsonEdge<'a> {
    id: &'a str,
    site_id: Option<&'a str>,
    source: &'a str,
    target: &'a str,
    kind: &'a str,
    phase: &'a str,
    environment: &'a str,
    profile_id: &'a str,
    resolution_status: &'a str,
    precision: &'a str,
    generated: bool,
}

fn write_agent_safe_export<W: Write>(
    snapshot: &GraphSnapshot,
    format: GraphExportFormat,
    writer: &mut W,
) -> anyhow::Result<()> {
    match format {
        GraphExportFormat::Json => write_agent_safe_json(snapshot, writer),
        GraphExportFormat::Dot => write_agent_safe_dot(snapshot, writer),
        GraphExportFormat::Mermaid => write_agent_safe_mermaid(snapshot, writer),
        GraphExportFormat::Graphml => write_agent_safe_graphml(snapshot, writer),
    }
}

fn write_agent_safe_json<W: Write>(snapshot: &GraphSnapshot, writer: &mut W) -> anyhow::Result<()> {
    let nodes = snapshot
        .nodes
        .iter()
        .map(|node| AgentSafeJsonNode {
            id: &node.id,
            kind: &node.kind,
            locator: &node.locator,
            display_name: &node.display_name,
        })
        .collect();
    let edges = snapshot
        .edges
        .iter()
        .map(|edge| AgentSafeJsonEdge {
            id: &edge.id,
            site_id: edge.site_id.as_deref(),
            source: &edge.source,
            target: &edge.target,
            kind: &edge.kind,
            phase: &edge.phase,
            environment: &edge.environment,
            profile_id: &edge.profile_id,
            resolution_status: &edge.resolution_status,
            precision: &edge.precision,
            generated: edge.generated,
        })
        .collect();
    serde_json::to_writer_pretty(
        writer,
        &AgentSafeJsonExport {
            schema_version: "depgraph-agent-graph-export-v1",
            nodes,
            edges,
        },
    )?;
    Ok(())
}

fn write_agent_safe_dot<W: Write>(snapshot: &GraphSnapshot, writer: &mut W) -> anyhow::Result<()> {
    writer.write_all(b"digraph depgraph {\n  rankdir=LR;\n")?;
    for node in &snapshot.nodes {
        writeln!(
            writer,
            "  \"{}\" [label=\"{}\\n({})\"];",
            dot_escape(&node.id),
            dot_escape(&node.display_name),
            dot_escape(&node.kind),
        )?;
    }
    for edge in &snapshot.edges {
        let label = format!(
            "{} [{}; {}; {}; {}; {}]",
            edge.kind,
            edge.phase,
            edge.resolution_status,
            edge.precision,
            edge.profile_id,
            edge.environment,
        );
        writeln!(
            writer,
            "  \"{}\" -> \"{}\" [label=\"{}\"];",
            dot_escape(&edge.source),
            dot_escape(&edge.target),
            dot_escape(&label),
        )?;
    }
    writer.write_all(b"}\n")?;
    Ok(())
}

fn write_agent_safe_mermaid<W: Write>(
    snapshot: &GraphSnapshot,
    writer: &mut W,
) -> anyhow::Result<()> {
    writer.write_all(b"flowchart LR\n")?;
    let indexes = snapshot
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    for (index, node) in snapshot.nodes.iter().enumerate() {
        writeln!(
            writer,
            "  n{index}[\"{}\\n({})\"]",
            mermaid_escape(&node.display_name),
            mermaid_escape(&node.kind),
        )?;
    }
    for edge in &snapshot.edges {
        let Some(source) = indexes.get(edge.source.as_str()) else {
            anyhow::bail!("export edge references a missing source node");
        };
        let Some(target) = indexes.get(edge.target.as_str()) else {
            anyhow::bail!("export edge references a missing target node");
        };
        writeln!(
            writer,
            "  n{source} -->|\"{} [{}; {}; {}; {}; {}]\"| n{target}",
            mermaid_escape(&edge.kind),
            mermaid_escape(&edge.phase),
            mermaid_escape(&edge.resolution_status),
            mermaid_escape(&edge.precision),
            mermaid_escape(&edge.profile_id),
            mermaid_escape(&edge.environment),
        )?;
    }
    Ok(())
}

fn write_agent_safe_graphml<W: Write>(
    snapshot: &GraphSnapshot,
    writer: &mut W,
) -> anyhow::Result<()> {
    let indexes = snapshot
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    writer.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
    writer.write_all(
        b"<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n  <key id=\"n_id\" for=\"node\" attr.name=\"depgraph.node.id\" attr.type=\"string\"/>\n  <key id=\"n_kind\" for=\"node\" attr.name=\"depgraph.node.kind\" attr.type=\"string\"/>\n  <key id=\"n_locator\" for=\"node\" attr.name=\"depgraph.node.locator\" attr.type=\"string\"/>\n  <key id=\"n_label\" for=\"node\" attr.name=\"depgraph.node.display_name\" attr.type=\"string\"/>\n  <key id=\"e_id\" for=\"edge\" attr.name=\"depgraph.edge.id\" attr.type=\"string\"/>\n  <key id=\"e_kind\" for=\"edge\" attr.name=\"depgraph.edge.kind\" attr.type=\"string\"/>\n  <key id=\"e_phase\" for=\"edge\" attr.name=\"depgraph.edge.phase\" attr.type=\"string\"/>\n  <key id=\"e_profile\" for=\"edge\" attr.name=\"depgraph.edge.profile_id\" attr.type=\"string\"/>\n  <graph id=\"depgraph\" edgedefault=\"directed\">\n",
    )?;
    for (index, node) in snapshot.nodes.iter().enumerate() {
        writeln!(writer, "    <node id=\"n{index}\">")?;
        write_graphml_data(writer, "n_id", &node.id, 6)?;
        write_graphml_data(writer, "n_kind", &node.kind, 6)?;
        write_graphml_data(writer, "n_locator", &node.locator, 6)?;
        write_graphml_data(writer, "n_label", &node.display_name, 6)?;
        writer.write_all(b"    </node>\n")?;
    }
    for (index, edge) in snapshot.edges.iter().enumerate() {
        let Some(source) = indexes.get(edge.source.as_str()) else {
            anyhow::bail!("export edge references a missing source node");
        };
        let Some(target) = indexes.get(edge.target.as_str()) else {
            anyhow::bail!("export edge references a missing target node");
        };
        writeln!(
            writer,
            "    <edge id=\"e{index}\" source=\"n{source}\" target=\"n{target}\">",
        )?;
        write_graphml_data(writer, "e_id", &edge.id, 6)?;
        write_graphml_data(writer, "e_kind", &edge.kind, 6)?;
        write_graphml_data(writer, "e_phase", &edge.phase, 6)?;
        write_graphml_data(writer, "e_profile", &edge.profile_id, 6)?;
        writer.write_all(b"    </edge>\n")?;
    }
    writer.write_all(b"  </graph>\n</graphml>\n")?;
    Ok(())
}

fn write_graphml_data<W: Write>(
    writer: &mut W,
    key: &str,
    value: &str,
    indent: usize,
) -> anyhow::Result<()> {
    writeln!(
        writer,
        "{}<data key=\"{}\">{}</data>",
        " ".repeat(indent),
        key,
        xml_escape(value),
    )?;
    Ok(())
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn mermaid_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', " ")
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

struct BoundedOutput {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
    cancellation: CancellationToken,
}

impl BoundedOutput {
    fn new(maximum: usize, cancellation: CancellationToken) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(64 * 1024)),
            maximum,
            exceeded: false,
            cancellation,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        if buffer.len() > self.maximum.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("inline export output limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn enforce_output_bound(
    service: &DepgraphService,
    value: &impl Serialize,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<()> {
    let maximum = service.config().limits().max_output_bytes();
    let mut output = BoundedOutput::new(maximum, cancellation.clone());
    if serde_json::to_writer(&mut output, value).is_err() {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        return Err(if output.exceeded {
            DepgraphServiceError::ResourceExhausted
        } else {
            DepgraphServiceError::Internal
        });
    }
    Ok(())
}

fn enforce_graph_export_output_bound(
    service: &DepgraphService,
    value: &GraphExportResult,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<()> {
    let maximum = service.config().limits().max_output_bytes();
    let reserve = GRAPH_EXPORT_ENVELOPE_RESERVE_BYTES.min(maximum);
    let result_maximum = maximum.saturating_sub(reserve);
    let mut output = BoundedOutput::new(result_maximum, cancellation.clone());
    if serde_json::to_writer(&mut output, value).is_err() {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        return Err(if output.exceeded {
            DepgraphServiceError::InlineExportTooLarge { maximum }
        } else {
            DepgraphServiceError::Internal
        });
    }
    Ok(())
}

fn check_cancelled(cancellation: &CancellationToken) -> DepgraphServiceResult<()> {
    if cancellation.is_cancelled() {
        Err(DepgraphServiceError::Cancelled)
    } else {
        Ok(())
    }
}

fn cancelled_or(
    error: DepgraphServiceError,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    if cancellation.is_cancelled() {
        DepgraphServiceError::Cancelled
    } else {
        error
    }
}

fn cancelled_or_store(
    source: anyhow::Error,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    cancelled_or(DepgraphServiceError::store_operation(source), cancellation)
}

fn cancelled_or_policy(
    _source: anyhow::Error,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    cancelled_or(DepgraphServiceError::PolicyInput, cancellation)
}

#[allow(dead_code)]
fn _closed_policy_kinds(_: PolicySelectorKind, _: EvidenceKind) {}
