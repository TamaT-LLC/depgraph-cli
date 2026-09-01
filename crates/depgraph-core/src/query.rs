use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{Condition, canonical_json, stable_id_from_value};
use depgraph_store::{
    DiagnosticRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, GraphTopology, NodeRecord,
    PhaseCoverageRecord, ProfileCorrelationRecord, ProfileMatrixRecord, SiteRecord,
    phase_coverage_for_effective_profile, runtime_context_for_edge,
};
use petgraph::{algo::tarjan_scc, graph::DiGraph};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::service_limits::{
    MAX_GRAPH_EVIDENCE_ITEMS, MAX_GRAPH_PHASE_COVERAGE_ITEMS,
    MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS, MAX_UNRESOLVED_CORRELATION_REASONS,
};

pub const INTERACTIVE_QUERY_PAGE_CONTRACT_VERSION: &str = "depgraph-interactive-query-page-v1";
pub const DEFAULT_INTERACTIVE_QUERY_MAX_ITEMS: usize = 100;
pub const DEFAULT_INTERACTIVE_QUERY_MAX_BYTES: usize = 1024 * 1024;
pub const DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL: usize = 50_000;
pub const MAX_INTERACTIVE_QUERY_ITEMS: usize = 10_000;
pub const MAX_INTERACTIVE_QUERY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_INTERACTIVE_QUERY_TRAVERSAL: usize = 1_000_000;
const MIN_INTERACTIVE_QUERY_BYTES: usize = 4 * 1024;
const MAX_QUERY_SUMMARY_GROUPS: usize = 64;
const INTERACTIVE_QUERY_CURSOR_PREFIX: &str = "depgraph-query-cursor-v1";

type CanonicalAdjacency<'a> = BTreeMap<&'a str, BTreeMap<(&'a str, &'a str), &'a EdgeRecord>>;

#[derive(Debug, thiserror::Error)]
#[error("graph selector preprocessing exceeded its service bound")]
struct SelectorPreprocessingExhausted;

#[derive(Debug, thiserror::Error)]
#[error("graph selector preprocessing was cancelled")]
struct SelectorPreprocessingCancelled;

#[derive(Debug, thiserror::Error)]
#[error("graph path-step postprocessing exceeded its service bound")]
struct QueryPostprocessingExhausted;

#[derive(Debug, thiserror::Error)]
#[error("graph path-step postprocessing was cancelled")]
struct QueryPostprocessingCancelled;

#[derive(Debug, thiserror::Error)]
#[error("graph path-step postprocessing found inconsistent correlation data")]
struct QueryPostprocessingIntegrity;

pub(crate) fn is_resource_exhausted(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<SelectorPreprocessingExhausted>()
        .is_some()
        || error
            .downcast_ref::<QueryPostprocessingExhausted>()
            .is_some()
}

pub(crate) fn is_cancelled(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<SelectorPreprocessingCancelled>()
        .is_some()
        || error
            .downcast_ref::<QueryPostprocessingCancelled>()
            .is_some()
}

pub(crate) fn is_integrity(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<QueryPostprocessingIntegrity>()
        .is_some()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryPageDiagnostic {
    pub code: String,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCountGroup {
    pub key: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCountSummary {
    pub groups: Vec<QueryCountGroup>,
    pub omitted_groups: u64,
    pub omitted_items: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractiveQuerySummary {
    pub total_items: u64,
    pub by_status: QueryCountSummary,
    pub by_phase: QueryCountSummary,
    pub by_profile: QueryCountSummary,
    pub by_kind: QueryCountSummary,
    pub by_reason: QueryCountSummary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InteractiveQueryPage<T> {
    pub schema_version: String,
    pub contract_version: String,
    pub command: String,
    pub scan_id: String,
    pub snapshot_id: String,
    pub complete: bool,
    pub returned_items: u64,
    pub total_items: u64,
    pub traversed_items: u64,
    pub serialized_output_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<NodeRecord>,
    pub summary: InteractiveQuerySummary,
    pub diagnostics: Vec<QueryPageDiagnostic>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub items: Vec<T>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundedTraversalResult {
    pub result: TraversalResult,
    pub complete: bool,
    pub traversed_edges: u64,
    pub diagnostics: Vec<QueryPageDiagnostic>,
}

#[derive(Debug, Clone)]
pub struct InteractiveQueryPageRequest<'a> {
    pub command: &'a str,
    pub scan_id: &'a str,
    pub snapshot_id: &'a str,
    pub context: &'a Value,
    pub cursor: Option<&'a str>,
    pub max_items: usize,
    pub max_bytes: usize,
    pub traversal_complete: bool,
    pub traversed_items: u64,
    pub root: Option<&'a NodeRecord>,
    pub diagnostics: Vec<QueryPageDiagnostic>,
}

pub fn validate_interactive_query_bounds(
    max_items: usize,
    max_bytes: usize,
    max_traversal: Option<usize>,
) -> Result<()> {
    if !(1..=MAX_INTERACTIVE_QUERY_ITEMS).contains(&max_items) {
        bail!("interactive query max-items must be in 1..={MAX_INTERACTIVE_QUERY_ITEMS}");
    }
    if !(MIN_INTERACTIVE_QUERY_BYTES..=MAX_INTERACTIVE_QUERY_BYTES).contains(&max_bytes) {
        bail!(
            "interactive query max-bytes must be in {MIN_INTERACTIVE_QUERY_BYTES}..={MAX_INTERACTIVE_QUERY_BYTES}"
        );
    }
    if let Some(max_traversal) = max_traversal
        && !(1..=MAX_INTERACTIVE_QUERY_TRAVERSAL).contains(&max_traversal)
    {
        bail!("interactive query max-traversal must be in 1..={MAX_INTERACTIVE_QUERY_TRAVERSAL}");
    }
    Ok(())
}

pub fn traversal_summary(result: &TraversalResult) -> InteractiveQuerySummary {
    summarize_query_items(
        result
            .steps
            .iter()
            .map(|step| step.edge.resolution_status.as_str()),
        result.steps.iter().map(|step| step.edge.phase.as_str()),
        result
            .steps
            .iter()
            .map(|step| step.edge.profile_id.as_str()),
        result.steps.iter().map(|step| step.edge.kind.as_str()),
        std::iter::empty(),
        result.steps.len(),
    )
}

pub fn traversal_page_items(result: &TraversalResult) -> Result<Vec<TraversalPageItem>> {
    let nodes = std::iter::once(&result.root)
        .chain(result.nodes.iter())
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    result
        .steps
        .iter()
        .map(|step| {
            let source = nodes.get(step.edge.source.as_str()).with_context(|| {
                format!(
                    "traversal page source node {} is unavailable",
                    step.edge.source
                )
            })?;
            let target = nodes.get(step.edge.target.as_str()).with_context(|| {
                format!(
                    "traversal page target node {} is unavailable",
                    step.edge.target
                )
            })?;
            Ok(TraversalPageItem {
                source: (*source).clone(),
                target: (*target).clone(),
                step: step.clone(),
            })
        })
        .collect()
}

pub fn unresolved_summary(result: &[UnresolvedResult]) -> InteractiveQuerySummary {
    summarize_query_items(
        result
            .iter()
            .map(|item| item.site.resolution_status.as_str()),
        result
            .iter()
            .flat_map(|item| item.phases.iter().map(String::as_str)),
        result.iter().map(|item| item.site.profile_id.as_str()),
        result.iter().map(|item| item.site.kind.as_str()),
        result
            .iter()
            .map(|item| item.site.reason.as_deref().unwrap_or("unspecified")),
        result.len(),
    )
}

fn summarize_query_items<'a>(
    statuses: impl Iterator<Item = &'a str>,
    phases: impl Iterator<Item = &'a str>,
    profiles: impl Iterator<Item = &'a str>,
    kinds: impl Iterator<Item = &'a str>,
    reasons: impl Iterator<Item = &'a str>,
    total_items: usize,
) -> InteractiveQuerySummary {
    InteractiveQuerySummary {
        total_items: total_items.try_into().unwrap_or(u64::MAX),
        by_status: bounded_count_summary(statuses),
        by_phase: bounded_count_summary(phases),
        by_profile: bounded_count_summary(profiles),
        by_kind: bounded_count_summary(kinds),
        by_reason: bounded_count_summary(reasons),
    }
}

fn bounded_count_summary<'a>(values: impl Iterator<Item = &'a str>) -> QueryCountSummary {
    let mut counts = BTreeMap::<String, u64>::new();
    for value in values {
        *counts.entry(value.to_owned()).or_default() += 1;
    }
    let mut groups = counts
        .into_iter()
        .map(|(key, count)| QueryCountGroup { key, count })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| right.count.cmp(&left.count).then(left.key.cmp(&right.key)));
    let omitted = groups.split_off(groups.len().min(MAX_QUERY_SUMMARY_GROUPS));
    QueryCountSummary {
        groups,
        omitted_groups: omitted.len().try_into().unwrap_or(u64::MAX),
        omitted_items: omitted.iter().map(|group| group.count).sum(),
    }
}

pub fn paginate_interactive_query<T>(
    items: &[T],
    summary: InteractiveQuerySummary,
    request: InteractiveQueryPageRequest<'_>,
) -> Result<InteractiveQueryPage<T>>
where
    T: Clone + Serialize,
{
    validate_interactive_query_bounds(request.max_items, request.max_bytes, None)?;
    let context_digest = stable_id_from_value(
        "interactive-query-context",
        &json!({
            "contract_version": INTERACTIVE_QUERY_PAGE_CONTRACT_VERSION,
            "command": request.command,
            "scan_id": request.scan_id,
            "snapshot_id": request.snapshot_id,
            "context": request.context,
        }),
    );
    let offset = request
        .cursor
        .map(|cursor| decode_interactive_query_cursor(cursor, &context_digest))
        .transpose()?
        .unwrap_or(0);
    if offset > items.len() {
        bail!("interactive query cursor is beyond the available canonical result");
    }

    let maximum_count = request.max_items.min(items.len() - offset);
    let mut maximum_page = build_interactive_query_page(
        items,
        &summary,
        &request,
        &context_digest,
        offset,
        maximum_count,
        false,
    );
    stabilize_serialized_output_bytes(&mut maximum_page)?;
    let maximum_fits = usize::try_from(maximum_page.serialized_output_bytes).unwrap_or(usize::MAX)
        <= request.max_bytes;
    let mut low = if maximum_fits { maximum_count } else { 0 };
    if !maximum_fits {
        let mut high = maximum_count.saturating_sub(1);
        while low < high {
            let count = low + (high - low).div_ceil(2);
            let mut page = build_interactive_query_page(
                items,
                &summary,
                &request,
                &context_digest,
                offset,
                count,
                false,
            );
            stabilize_serialized_output_bytes(&mut page)?;
            if usize::try_from(page.serialized_output_bytes).unwrap_or(usize::MAX)
                <= request.max_bytes
            {
                low = count;
            } else {
                high = count - 1;
            }
        }
    }

    let remaining_item_exceeds_budget = low == 0 && offset < items.len();
    let mut page = build_interactive_query_page(
        items,
        &summary,
        &request,
        &context_digest,
        offset,
        low,
        remaining_item_exceeds_budget,
    );
    stabilize_serialized_output_bytes(&mut page)?;
    if usize::try_from(page.serialized_output_bytes).unwrap_or(usize::MAX) > request.max_bytes {
        bail!(
            "interactive query max-bytes is too small for the bounded summary metadata; increase --max-bytes"
        );
    }
    Ok(page)
}

fn build_interactive_query_page<T>(
    items: &[T],
    summary: &InteractiveQuerySummary,
    request: &InteractiveQueryPageRequest<'_>,
    context_digest: &str,
    offset: usize,
    count: usize,
    remaining_item_exceeds_budget: bool,
) -> InteractiveQueryPage<T>
where
    T: Clone,
{
    let page_end = offset + count;
    let output_truncated = page_end < items.len();
    let complete = request.traversal_complete && !output_truncated;
    let mut diagnostics = request.diagnostics.clone();
    if remaining_item_exceeds_budget {
        diagnostics.push(QueryPageDiagnostic {
            code: "QUERY_ITEM_EXCEEDS_BYTE_BUDGET".to_owned(),
            message: format!(
                "the next canonical item does not fit within the {}-byte output budget",
                request.max_bytes
            ),
            remediation: "rerun the same cursor with a larger --max-bytes value".to_owned(),
        });
    } else if output_truncated {
        diagnostics.push(QueryPageDiagnostic {
            code: "QUERY_OUTPUT_TRUNCATED".to_owned(),
            message: format!(
                "returned {count} canonical items from offset {offset} before the configured output limit"
            ),
            remediation: "resume with next_cursor, or use --all for an explicit full result"
                .to_owned(),
        });
    }
    diagnostics.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then(left.message.cmp(&right.message))
    });
    diagnostics.dedup();
    let next_cursor = (output_truncated && !remaining_item_exceeds_budget)
        .then(|| encode_interactive_query_cursor(context_digest, page_end));
    InteractiveQueryPage {
        schema_version: "1.0".to_owned(),
        contract_version: INTERACTIVE_QUERY_PAGE_CONTRACT_VERSION.to_owned(),
        command: request.command.to_owned(),
        scan_id: request.scan_id.to_owned(),
        snapshot_id: request.snapshot_id.to_owned(),
        complete,
        returned_items: count.try_into().unwrap_or(u64::MAX),
        total_items: summary.total_items,
        traversed_items: request.traversed_items,
        serialized_output_bytes: 0,
        root: request.root.cloned(),
        summary: summary.clone(),
        diagnostics,
        next_cursor,
        items: items[offset..page_end].to_vec(),
    }
}

fn serialized_page_len<T: Serialize>(page: &InteractiveQueryPage<T>) -> Result<usize> {
    Ok(canonical_json(&serde_json::to_value(page)?).len())
}

fn stabilize_serialized_output_bytes<T: Serialize>(
    page: &mut InteractiveQueryPage<T>,
) -> Result<()> {
    for _ in 0..8 {
        let length = serialized_page_len(page)?;
        let length = length.try_into().unwrap_or(u64::MAX);
        if page.serialized_output_bytes == length {
            return Ok(());
        }
        page.serialized_output_bytes = length;
    }
    bail!("interactive query output byte accounting did not converge")
}

fn encode_interactive_query_cursor(context_digest: &str, offset: usize) -> String {
    let signature = stable_id_from_value(
        "interactive-query-cursor",
        &json!({
            "context_digest": context_digest,
            "offset": offset,
        }),
    );
    let signature = signature.rsplit(':').next().unwrap_or(signature.as_str());
    format!("{INTERACTIVE_QUERY_CURSOR_PREFIX}.{offset}.{signature}")
}

fn decode_interactive_query_cursor(cursor: &str, context_digest: &str) -> Result<usize> {
    let mut parts = cursor.split('.');
    let prefix = parts.next();
    let raw_offset = parts.next();
    let signature = parts.next();
    if prefix != Some(INTERACTIVE_QUERY_CURSOR_PREFIX)
        || parts.next().is_some()
        || signature.is_none_or(|value| {
            value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        bail!("interactive query cursor is malformed");
    }
    let raw_offset = raw_offset.context("interactive query cursor is malformed")?;
    let offset = raw_offset
        .parse::<usize>()
        .context("interactive query cursor has an invalid offset")?;
    if offset.to_string() != raw_offset {
        bail!("interactive query cursor offset is not canonical");
    }
    let expected = encode_interactive_query_cursor(context_digest, offset);
    if expected != cursor {
        bail!("interactive query cursor does not match this snapshot and query");
    }
    Ok(offset)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleLevel {
    Package,
    File,
    Symbol,
    Type,
    Route,
}

impl CycleLevel {
    pub(crate) const fn node_kind(self) -> &'static str {
        match self {
            Self::Package => "package_instance",
            Self::File => "file",
            Self::Symbol => "symbol",
            Self::Type => "type",
            Self::Route => "route",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraversalResult {
    pub root: NodeRecord,
    pub nodes: Vec<NodeRecord>,
    pub edges: Vec<EdgeRecord>,
    pub steps: Vec<PathStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraversalPageItem {
    pub source: NodeRecord,
    pub target: NodeRecord,
    pub step: PathStep,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathStep {
    pub edge: EdgeRecord,
    pub condition_text: String,
    pub evidence: Vec<EvidenceRecord>,
    pub effective_profile_id: Option<String>,
    pub correlation_status: Option<String>,
    pub observed_difference_reasons: Vec<String>,
    pub phase_coverage: BTreeMap<String, PhaseCoverageRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WhyResult {
    pub from: NodeRecord,
    pub to: NodeRecord,
    pub path_found: bool,
    pub steps: Vec<PathStep>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CycleResult {
    pub level: String,
    pub node_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnresolvedResult {
    pub site: SiteRecord,
    pub evidence: Vec<EvidenceRecord>,
    #[serde(skip_serializing)]
    pub phases: Vec<String>,
    pub effective_profile_id: Option<String>,
    pub correlation_status: Option<String>,
    pub observed_difference_reasons: Vec<String>,
    pub phase_coverage: BTreeMap<String, PhaseCoverageRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphQueryFilter {
    pub phases: Vec<String>,
    pub profiles: Vec<String>,
    pub sessions: Vec<String>,
    pub environments: Vec<String>,
}

impl GraphQueryFilter {
    pub fn new(
        phases: Vec<String>,
        profiles: Vec<String>,
        sessions: Vec<String>,
        environments: Vec<String>,
    ) -> Result<Self> {
        Ok(Self {
            phases: normalize_query_filter("phase", phases)?,
            profiles: normalize_query_filter("profile", profiles)?,
            sessions: normalize_query_filter("session", sessions)?,
            environments: normalize_query_filter("environment", environments)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.phases.is_empty()
            && self.profiles.is_empty()
            && self.sessions.is_empty()
            && self.environments.is_empty()
    }

    pub fn matches_edge(&self, snapshot: &GraphSnapshot, edge: &EdgeRecord) -> bool {
        if !self.phases.is_empty() && self.phases.binary_search(&edge.phase).is_err() {
            return false;
        }
        if !self.profiles.is_empty() && self.profiles.binary_search(&edge.profile_id).is_err() {
            return false;
        }
        if self.sessions.is_empty() && self.environments.is_empty() {
            return true;
        }
        if edge.phase != "runtime" {
            return false;
        }
        let context = runtime_context_for_edge(snapshot, edge);
        let session_matches = self.sessions.is_empty()
            || context
                .session_ids
                .iter()
                .chain(context.source_session_ids.iter())
                .any(|value| self.sessions.binary_search(value).is_ok());
        let environment_matches = self.environments.is_empty()
            || context
                .environment_names
                .iter()
                .chain(context.runtimes.iter())
                .chain(context.regions.iter())
                .any(|value| self.environments.binary_search(value).is_ok());
        session_matches && environment_matches
    }

    pub fn matches_evidence(&self, evidence: &EvidenceRecord) -> bool {
        if evidence.kind != "runtime" {
            return self.sessions.is_empty() && self.environments.is_empty();
        }
        let session_matches = self.sessions.is_empty()
            || ["session_id", "source_session_id"].iter().any(|key| {
                evidence
                    .properties
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| self.sessions.iter().any(|item| item == value))
            });
        let environment_matches = self.environments.is_empty()
            || evidence
                .properties
                .get("environment")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|environment| {
                    ["name", "runtime", "region"].iter().any(|key| {
                        environment
                            .get(*key)
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|value| self.environments.iter().any(|item| item == value))
                    })
                });
        session_matches && environment_matches
    }

    pub fn matches_diagnostic(&self, diagnostic: &DiagnosticRecord) -> bool {
        let string_property_matches = |key: &str, values: &[String]| {
            values.is_empty()
                || diagnostic
                    .properties
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| values.iter().any(|item| item == value))
        };
        let phase_matches = string_property_matches("phase", &self.phases);
        let profile_matches = string_property_matches("profile_id", &self.profiles);
        let session_matches = self.sessions.is_empty()
            || ["session_id", "source_session_id"].iter().any(|key| {
                diagnostic
                    .properties
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| self.sessions.iter().any(|item| item == value))
            });
        let environment_matches = self.environments.is_empty()
            || diagnostic
                .properties
                .get("environment")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|environment| {
                    ["name", "runtime", "region"].iter().any(|key| {
                        environment
                            .get(*key)
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|value| self.environments.iter().any(|item| item == value))
                    })
                });
        phase_matches && profile_matches && session_matches && environment_matches
    }
}

fn normalize_query_filter(name: &str, values: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            bail!("{name} filter must not be empty");
        }
        normalized.push(value.to_owned());
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

pub fn resolve_selector(snapshot: &GraphSnapshot, selector: &str) -> Result<NodeRecord> {
    resolve_selector_bounded_cancellable(
        snapshot,
        selector,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        &mut || false,
    )
}

pub(crate) fn resolve_selector_bounded_cancellable(
    snapshot: &GraphSnapshot,
    selector: &str,
    maximum_work: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<NodeRecord> {
    let (kind, query) = selector
        .split_once(':')
        .filter(|(prefix, _)| {
            matches!(
                *prefix,
                "id" | "path" | "package" | "route" | "symbol" | "type"
            )
        })
        .unwrap_or(("bare", selector));
    let query = query.trim();
    if query.is_empty() {
        bail!("selector must not be empty");
    }

    let mut work = SelectorWork::new(maximum_work);
    let mut exact = SelectorCandidates::default();
    let mut partial = SelectorCandidates::default();
    for (ordinal, node) in snapshot.nodes.iter().enumerate() {
        work.step(is_cancelled)?;
        #[cfg(test)]
        SELECTOR_NODE_SCAN_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let kind_matches = match kind {
            "package" => node.kind == "package_instance",
            "route" => node.kind == "route",
            "path" => node.kind == "file",
            "symbol" => node.kind == "symbol",
            "type" => node.kind == "type",
            _ => true,
        };
        if !kind_matches {
            continue;
        }
        let values = [&node.id, &node.locator, &node.display_name];
        let path_matches = kind == "path"
            && node
                .properties
                .get("path")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|path| path == query);
        let resolver_identity_matches = matches!(kind, "symbol" | "type")
            && node
                .properties
                .get("canonical_identity")
                .and_then(|identity| identity.get("resolver_identity"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|identity| identity == query);
        let exact_match = if kind == "id" {
            node.id == query
        } else {
            path_matches
                || resolver_identity_matches
                || values.iter().any(|value| value.as_str() == query)
        };
        if exact_match {
            work.step(is_cancelled)?;
            exact.insert(node, ordinal)?;
            #[cfg(test)]
            SELECTOR_CANDIDATE_INSERT_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if values.iter().any(|value| value.contains(query)) {
            work.step(is_cancelled)?;
            partial.insert(node, ordinal)?;
            #[cfg(test)]
            SELECTOR_CANDIDATE_INSERT_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    choose_unique_bounded_cancellable(
        selector,
        if exact.is_empty() && kind != "id" {
            partial
        } else {
            exact
        },
        &mut work,
        is_cancelled,
    )
}

fn choose_unique_bounded_cancellable(
    selector: &str,
    mut candidates: SelectorCandidates<'_>,
    work: &mut SelectorWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<NodeRecord> {
    match candidates.count {
        0 => bail!("selector {selector:?} did not match any node"),
        1 => {
            work.step(is_cancelled)?;
            candidates
                .first
                .pop_first()
                .map(|(_, node)| node.clone())
                .context("selector candidate disappeared during finalization")
        }
        _ => {
            let mut choices = Vec::with_capacity(candidates.first.len());
            for node in candidates.first.into_values() {
                work.step(is_cancelled)?;
                choices.push(format!("{} ({}, id:{})", node.locator, node.kind, node.id));
            }
            let choices = choices.join(", ");
            bail!(
                "selector {selector:?} is ambiguous; select a candidate with id:<stable-id>. candidates: {choices}"
            )
        }
    }
}

#[derive(Default)]
struct SelectorCandidates<'a> {
    count: usize,
    first: BTreeMap<(&'a str, usize), &'a NodeRecord>,
}

impl<'a> SelectorCandidates<'a> {
    const fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn insert(&mut self, node: &'a NodeRecord, ordinal: usize) -> Result<()> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or(SelectorPreprocessingExhausted)?;
        let key = (node.id.as_str(), ordinal);
        if self.first.len() < 10 {
            self.first.insert(key, node);
        } else if self
            .first
            .last_key_value()
            .is_some_and(|(last, _)| key < *last)
        {
            self.first.pop_last();
            self.first.insert(key, node);
        }
        Ok(())
    }
}

struct SelectorWork {
    used: usize,
    maximum: usize,
}

impl SelectorWork {
    const fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    fn step(&mut self, is_cancelled: &mut impl FnMut() -> bool) -> Result<()> {
        if is_cancelled() {
            return Err(SelectorPreprocessingCancelled.into());
        }
        if self.used >= self.maximum {
            return Err(SelectorPreprocessingExhausted.into());
        }
        self.used += 1;
        #[cfg(test)]
        SELECTOR_WORK_ITEMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
static SELECTOR_WORK_ITEMS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static SELECTOR_NODE_SCAN_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static SELECTOR_CANDIDATE_INSERT_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub fn traverse(
    snapshot: &GraphSnapshot,
    selector: &str,
    transitive: bool,
    reverse: bool,
) -> Result<TraversalResult> {
    traverse_filtered(
        snapshot,
        selector,
        transitive,
        reverse,
        &GraphQueryFilter::default(),
    )
}

pub fn traverse_filtered(
    snapshot: &GraphSnapshot,
    selector: &str,
    transitive: bool,
    reverse: bool,
    filter: &GraphQueryFilter,
) -> Result<TraversalResult> {
    Ok(
        traverse_bounded_filtered(snapshot, selector, transitive, reverse, filter, usize::MAX)?
            .result,
    )
}

pub fn traverse_bounded_filtered(
    snapshot: &GraphSnapshot,
    selector: &str,
    transitive: bool,
    reverse: bool,
    filter: &GraphQueryFilter,
    max_traversal: usize,
) -> Result<BoundedTraversalResult> {
    traverse_bounded_filtered_cancellable(
        snapshot,
        selector,
        transitive,
        reverse,
        filter,
        max_traversal,
        || false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn traverse_bounded_filtered_cancellable(
    snapshot: &GraphSnapshot,
    selector: &str,
    transitive: bool,
    reverse: bool,
    filter: &GraphQueryFilter,
    max_traversal: usize,
    is_cancelled: impl FnMut() -> bool,
) -> Result<BoundedTraversalResult> {
    traverse_bounded_filtered_cancellable_with_adjacency_limit(
        snapshot,
        selector,
        transitive,
        reverse,
        filter,
        max_traversal,
        MAX_INTERACTIVE_QUERY_TRAVERSAL,
        is_cancelled,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn traverse_bounded_filtered_cancellable_with_adjacency_limit(
    snapshot: &GraphSnapshot,
    selector: &str,
    transitive: bool,
    reverse: bool,
    filter: &GraphQueryFilter,
    max_traversal: usize,
    max_adjacency_inspection: usize,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<BoundedTraversalResult> {
    if is_cancelled() {
        bail!("dependency traversal was cancelled");
    }
    let root = resolve_selector_bounded_cancellable(
        snapshot,
        selector,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        &mut is_cancelled,
    )?;
    let (adjacency, adjacency_complete) = adjacency_cancellable(
        snapshot,
        reverse,
        filter,
        max_adjacency_inspection,
        &mut is_cancelled,
    )?;
    let mut queue = VecDeque::from([root.id.clone()]);
    let mut visited = BTreeSet::from([root.id.clone()]);
    let mut selected_edges = BTreeMap::new();
    let mut traversed_edges = 0_usize;
    let mut complete = adjacency_complete;

    'traversal: while let Some(node_id) = queue.pop_front() {
        if is_cancelled() {
            bail!("dependency traversal was cancelled");
        }
        if let Some(edges) = adjacency.get(node_id.as_str()) {
            for edge in edges.values() {
                if is_cancelled() {
                    bail!("dependency traversal was cancelled");
                }
                if traversed_edges >= max_traversal {
                    complete = false;
                    break 'traversal;
                }
                traversed_edges += 1;
                selected_edges.insert(edge.id.clone(), *edge);
                let next = if reverse { &edge.source } else { &edge.target };
                if visited.insert(next.clone()) && transitive {
                    queue.push_back(next.clone());
                }
            }
        }
        if !transitive {
            break;
        }
    }

    let mut node_work = SelectorWork::new(MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS);
    let mut selected_nodes = BTreeMap::new();
    for node in &snapshot.nodes {
        node_work.step(&mut is_cancelled)?;
        if node.id != root.id && visited.contains(&node.id) {
            node_work.step(&mut is_cancelled)?;
            selected_nodes.insert(node.id.clone(), node.clone());
        }
    }
    let mut nodes = Vec::with_capacity(selected_nodes.len());
    for node in selected_nodes.into_values() {
        node_work.step(&mut is_cancelled)?;
        nodes.push(node);
    }
    let mut materializer = PathStepMaterializer::new(
        snapshot,
        filter,
        selected_edges.values().copied(),
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        &mut is_cancelled,
    )?;
    let mut edges = Vec::with_capacity(selected_edges.len());
    let mut steps = Vec::with_capacity(selected_edges.len());
    for edge in selected_edges.into_values() {
        steps.push(materializer.materialize(edge, &mut is_cancelled)?);
        edges.push(materializer.clone_edge_output(edge, &mut is_cancelled)?);
    }
    let diagnostics = (!complete)
        .then(|| QueryPageDiagnostic {
            code: "QUERY_TRAVERSAL_LIMIT_REACHED".to_owned(),
            message: if adjacency_complete {
                format!(
                    "dependency traversal stopped after {traversed_edges} edge visits (limit {max_traversal})"
                )
            } else {
                format!(
                    "dependency adjacency preprocessing stopped after inspecting {} snapshot edges; result is partial",
                    max_adjacency_inspection
                )
            },
            remediation: if adjacency_complete {
                "rerun with a larger --max-traversal value or narrow the query filters".to_owned()
            } else {
                "reduce the snapshot size or narrow the configured scan scope".to_owned()
            },
        })
        .into_iter()
        .collect();
    Ok(BoundedTraversalResult {
        result: TraversalResult {
            root,
            nodes,
            edges,
            steps,
        },
        complete,
        traversed_edges: traversed_edges.try_into().unwrap_or(u64::MAX),
        diagnostics,
    })
}

pub fn why(snapshot: &GraphSnapshot, from: &str, to: &str) -> Result<WhyResult> {
    why_filtered(snapshot, from, to, &GraphQueryFilter::default())
}

pub fn why_filtered(
    snapshot: &GraphSnapshot,
    from: &str,
    to: &str,
    filter: &GraphQueryFilter,
) -> Result<WhyResult> {
    let from = resolve_selector(snapshot, from)?;
    let to = resolve_selector(snapshot, to)?;
    if from.id == to.id {
        return Ok(WhyResult {
            from,
            to,
            path_found: true,
            steps: Vec::new(),
        });
    }
    let (adjacency, complete) = adjacency_cancellable(
        snapshot,
        false,
        filter,
        MAX_INTERACTIVE_QUERY_TRAVERSAL,
        &mut || false,
    )?;
    if !complete {
        return Err(QueryPostprocessingExhausted.into());
    }
    let mut queue = VecDeque::from([from.id.clone()]);
    let mut seen = BTreeSet::from([from.id.clone()]);
    let mut predecessor: HashMap<String, &EdgeRecord> = HashMap::new();
    while let Some(node_id) = queue.pop_front() {
        if let Some(edges) = adjacency.get(node_id.as_str()) {
            for edge in edges.values() {
                if seen.insert(edge.target.clone()) {
                    predecessor.insert(edge.target.clone(), edge);
                    if edge.target == to.id {
                        queue.clear();
                        break;
                    }
                    queue.push_back(edge.target.clone());
                }
            }
        }
    }
    if !predecessor.contains_key(&to.id) {
        return Ok(WhyResult {
            from,
            to,
            path_found: false,
            steps: Vec::new(),
        });
    }
    let mut current = to.id.clone();
    let mut reversed_edges = Vec::new();
    while current != from.id {
        if reversed_edges.len() >= crate::service_limits::MAX_DEPENDENCY_PATH_STEPS {
            return Err(QueryPostprocessingExhausted.into());
        }
        let edge = predecessor
            .get(&current)
            .with_context(|| format!("path reconstruction failed at {current}"))?;
        reversed_edges.push(*edge);
        current = edge.source.clone();
    }
    reversed_edges.reverse();
    let steps = materialize_path_steps_bounded_cancellable(
        snapshot,
        filter,
        &reversed_edges,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        &mut || false,
    )?;
    Ok(WhyResult {
        from,
        to,
        path_found: true,
        steps,
    })
}

pub fn cycles(snapshot: &GraphSnapshot, level: CycleLevel) -> Vec<CycleResult> {
    cycles_from_parts(
        snapshot
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node.kind.as_str())),
        snapshot
            .edges
            .iter()
            .map(|edge| (edge.source.as_str(), edge.target.as_str())),
        level,
    )
}

pub fn cycles_from_topology(topology: &GraphTopology, level: CycleLevel) -> Vec<CycleResult> {
    cycles_from_parts(
        topology
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node.kind.as_str())),
        topology
            .edges
            .iter()
            .map(|edge| (edge.source.as_str(), edge.target.as_str())),
        level,
    )
}

fn cycles_from_parts<'a>(
    nodes: impl IntoIterator<Item = (&'a str, &'a str)>,
    edges: impl IntoIterator<Item = (&'a str, &'a str)>,
    level: CycleLevel,
) -> Vec<CycleResult> {
    let allowed: BTreeSet<_> = nodes
        .into_iter()
        .filter(|(_, kind)| *kind == level.node_kind())
        .map(|(id, _)| id)
        .collect();
    let mut graph = DiGraph::<String, ()>::new();
    let mut indexes = BTreeMap::new();
    for id in &allowed {
        indexes.insert(*id, graph.add_node((*id).to_owned()));
    }
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (source, target) in edges {
        if allowed.contains(source) && allowed.contains(target) {
            graph.add_edge(indexes[source], indexes[target], ());
            adjacency
                .entry(source.to_owned())
                .or_default()
                .push(target.to_owned());
        }
    }
    for targets in adjacency.values_mut() {
        targets.sort();
        targets.dedup();
    }
    let mut results = Vec::new();
    for component in tarjan_scc(&graph) {
        let mut ids: Vec<_> = component
            .iter()
            .map(|index| graph[*index].clone())
            .collect();
        ids.sort();
        let self_loop = ids.len() == 1
            && adjacency
                .get(&ids[0])
                .is_some_and(|targets| targets.contains(&ids[0]));
        if ids.len() < 2 && !self_loop {
            continue;
        }
        let component_set: BTreeSet<_> = ids.iter().cloned().collect();
        let cycle =
            representative_cycle(&ids[0], &component_set, &adjacency).unwrap_or_else(|| {
                let mut fallback = ids.clone();
                fallback.push(ids[0].clone());
                fallback
            });
        results.push(CycleResult {
            level: level.node_kind().to_owned(),
            node_ids: cycle,
        });
    }
    results.sort_by(|left, right| left.node_ids.cmp(&right.node_ids));
    results
}

fn representative_cycle(
    start: &str,
    component: &BTreeSet<String>,
    adjacency: &BTreeMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    let mut queue = VecDeque::new();
    let mut predecessor: HashMap<String, String> = HashMap::new();
    for next in adjacency.get(start).into_iter().flatten() {
        if !component.contains(next) {
            continue;
        }
        if next == start {
            return Some(vec![start.to_owned(), start.to_owned()]);
        }
        predecessor.insert(next.clone(), start.to_owned());
        queue.push_back(next.clone());
    }
    while let Some(node) = queue.pop_front() {
        for next in adjacency.get(&node).into_iter().flatten() {
            if !component.contains(next) {
                continue;
            }
            if next == start {
                let mut path = vec![node.clone()];
                let mut current = node;
                while current != start {
                    current = predecessor.get(&current)?.clone();
                    path.push(current.clone());
                }
                path.reverse();
                path.push(start.to_owned());
                return Some(path);
            }
            if !predecessor.contains_key(next) {
                predecessor.insert(next.clone(), node.clone());
                queue.push_back(next.clone());
            }
        }
    }
    None
}

pub fn unresolved(snapshot: &GraphSnapshot) -> Vec<UnresolvedResult> {
    let evidence = snapshot
        .evidence
        .iter()
        .filter(|item| item.owner_type == "site")
        .fold(
            BTreeMap::<String, Vec<EvidenceRecord>>::new(),
            |mut map, item| {
                map.entry(item.owner_id.clone())
                    .or_default()
                    .push(item.clone());
                map
            },
        );
    let phases = snapshot.edges.iter().fold(
        BTreeMap::<String, BTreeSet<String>>::new(),
        |mut map, edge| {
            if let Some(site_id) = &edge.site_id {
                map.entry(site_id.clone())
                    .or_default()
                    .insert(edge.phase.clone());
            }
            map
        },
    );
    let correlations = site_correlation_map(&snapshot.profile_matrix);
    snapshot
        .sites
        .iter()
        .filter(|site| site.resolution_status == "unresolved")
        .map(|site| {
            let correlation = correlations.get(site.id.as_str()).copied();
            UnresolvedResult {
                site: site.clone(),
                evidence: evidence.get(&site.id).cloned().unwrap_or_default(),
                phases: phases
                    .get(&site.id)
                    .map(|values| values.iter().cloned().collect())
                    .unwrap_or_default(),
                effective_profile_id: correlation
                    .map(|correlation| correlation.effective_profile_id.clone()),
                correlation_status: correlation.map(|correlation| correlation.status.clone()),
                observed_difference_reasons: correlation
                    .map(|correlation| correlation.difference_reasons.clone())
                    .unwrap_or_default(),
                phase_coverage: correlation
                    .map(|correlation| {
                        phase_coverage_for_effective_profile(
                            &snapshot.profile_matrix,
                            &correlation.effective_profile_id,
                        )
                    })
                    .unwrap_or_default(),
            }
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum QueryPostprocessingStage {
    EdgeSelection,
    EvidenceScan,
    EvidenceOwnerInsertion,
    EvidenceOwnerFinalization,
    EvidenceClone,
    CorrelationRecord,
    CorrelationPhase,
    CorrelationEdge,
    CorrelationInsertion,
    ProfileEntry,
    ProfileInsertion,
    EdgeLookup,
    PathStep,
    ReasonClone,
    PhaseEntryClone,
    PhaseProfileClone,
    PhaseCompletenessClone,
    EdgeOutput,
}

const QUERY_POSTPROCESSING_STAGE_COUNT: usize = 18;

pub(crate) struct QueryPostprocessingWork {
    used: usize,
    maximum: usize,
    stage_counts: [usize; QUERY_POSTPROCESSING_STAGE_COUNT],
    #[cfg(test)]
    cancel_after: Option<(QueryPostprocessingStage, usize)>,
}

impl QueryPostprocessingWork {
    fn new(maximum: usize) -> Self {
        Self {
            used: 0,
            maximum,
            stage_counts: [0; QUERY_POSTPROCESSING_STAGE_COUNT],
            #[cfg(test)]
            cancel_after: None,
        }
    }

    #[cfg(test)]
    fn with_stage_cancellation(
        maximum: usize,
        stage: QueryPostprocessingStage,
        completed_steps: usize,
    ) -> Self {
        Self {
            used: 0,
            maximum,
            stage_counts: [0; QUERY_POSTPROCESSING_STAGE_COUNT],
            cancel_after: Some((stage, completed_steps)),
        }
    }

    fn step(
        &mut self,
        stage: QueryPostprocessingStage,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<()> {
        if is_cancelled() {
            return Err(QueryPostprocessingCancelled.into());
        }
        #[cfg(test)]
        if self.cancel_after.is_some_and(|(cancel_stage, completed)| {
            cancel_stage == stage && self.stage_counts[stage as usize] >= completed
        }) {
            return Err(QueryPostprocessingCancelled.into());
        }
        if self.used >= self.maximum {
            return Err(QueryPostprocessingExhausted.into());
        }
        self.used += 1;
        self.stage_counts[stage as usize] += 1;
        Ok(())
    }

    #[cfg(test)]
    fn used(&self) -> usize {
        self.used
    }

    #[cfg(test)]
    fn stage_count(&self, stage: QueryPostprocessingStage) -> usize {
        self.stage_counts[stage as usize]
    }
}

#[derive(Debug)]
struct PathStepProjection<'a> {
    evidence: BTreeMap<&'a str, Vec<EvidenceRecord>>,
    correlations: BTreeMap<&'a str, &'a ProfileCorrelationRecord>,
    phase_coverage: BTreeMap<&'a str, &'a BTreeMap<String, PhaseCoverageRecord>>,
}

impl<'a> PathStepProjection<'a> {
    fn build(
        snapshot: &'a GraphSnapshot,
        filter: &GraphQueryFilter,
        selected_edge_ids: &BTreeSet<&str>,
        work: &mut QueryPostprocessingWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self> {
        let mut evidence_refs = BTreeMap::<&str, Vec<&EvidenceRecord>>::new();
        for item in &snapshot.evidence {
            work.step(QueryPostprocessingStage::EvidenceScan, is_cancelled)?;
            if item.owner_type != "edge"
                || !selected_edge_ids.contains(item.owner_id.as_str())
                || !filter.matches_evidence(item)
            {
                continue;
            }
            work.step(
                QueryPostprocessingStage::EvidenceOwnerInsertion,
                is_cancelled,
            )?;
            let records = evidence_refs.entry(item.owner_id.as_str()).or_default();
            if records.len() >= MAX_GRAPH_EVIDENCE_ITEMS {
                return Err(QueryPostprocessingExhausted.into());
            }
            records.push(item);
        }

        let mut evidence = BTreeMap::new();
        for (owner_id, records) in &mut evidence_refs {
            work.step(
                QueryPostprocessingStage::EvidenceOwnerFinalization,
                is_cancelled,
            )?;
            records.sort_by(|left, right| evidence_order(left, right));
            work.step(
                QueryPostprocessingStage::EvidenceOwnerFinalization,
                is_cancelled,
            )?;
            let mut cloned = Vec::with_capacity(records.len());
            for record in records {
                work.step(QueryPostprocessingStage::EvidenceClone, is_cancelled)?;
                cloned.push((*record).clone());
            }
            evidence.insert(*owner_id, cloned);
        }

        let mut correlations = BTreeMap::new();
        let mut effective_profile_ids = BTreeSet::new();
        for correlation in &snapshot.profile_matrix.correlations {
            work.step(QueryPostprocessingStage::CorrelationRecord, is_cancelled)?;
            for edge_ids in correlation.edge_ids_by_phase.values() {
                work.step(QueryPostprocessingStage::CorrelationPhase, is_cancelled)?;
                for edge_id in edge_ids {
                    work.step(QueryPostprocessingStage::CorrelationEdge, is_cancelled)?;
                    if !selected_edge_ids.contains(edge_id.as_str()) {
                        continue;
                    }
                    if correlation.difference_reasons.len() > MAX_UNRESOLVED_CORRELATION_REASONS {
                        return Err(QueryPostprocessingExhausted.into());
                    }
                    work.step(QueryPostprocessingStage::CorrelationInsertion, is_cancelled)?;
                    if correlations.insert(edge_id.as_str(), correlation).is_some() {
                        return Err(QueryPostprocessingIntegrity.into());
                    }
                    if !effective_profile_ids.contains(correlation.effective_profile_id.as_str()) {
                        work.step(QueryPostprocessingStage::CorrelationInsertion, is_cancelled)?;
                        effective_profile_ids.insert(correlation.effective_profile_id.as_str());
                    }
                }
            }
        }

        let mut phase_coverage = BTreeMap::new();
        for entry in &snapshot.profile_matrix.entries {
            work.step(QueryPostprocessingStage::ProfileEntry, is_cancelled)?;
            if !effective_profile_ids.contains(entry.id.as_str())
                || phase_coverage.contains_key(entry.id.as_str())
            {
                continue;
            }
            if entry.phase_coverage.len() > MAX_GRAPH_PHASE_COVERAGE_ITEMS {
                return Err(QueryPostprocessingExhausted.into());
            }
            work.step(QueryPostprocessingStage::ProfileInsertion, is_cancelled)?;
            phase_coverage.insert(entry.id.as_str(), &entry.phase_coverage);
        }

        Ok(Self {
            evidence,
            correlations,
            phase_coverage,
        })
    }

    fn materialize(
        &self,
        edge: &EdgeRecord,
        work: &mut QueryPostprocessingWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<PathStep> {
        work.step(QueryPostprocessingStage::EdgeLookup, is_cancelled)?;
        let evidence = self.evidence.get(edge.id.as_str());
        let correlation = self.correlations.get(edge.id.as_str()).copied();

        work.step(QueryPostprocessingStage::PathStep, is_cancelled)?;
        let mut cloned_evidence = Vec::with_capacity(evidence.map_or(0, Vec::len));
        if let Some(evidence) = evidence {
            for record in evidence {
                work.step(QueryPostprocessingStage::EvidenceClone, is_cancelled)?;
                cloned_evidence.push(record.clone());
            }
        }

        let mut observed_difference_reasons = Vec::new();
        let mut phase_coverage = BTreeMap::new();
        if let Some(correlation) = correlation {
            if correlation.difference_reasons.len() > MAX_UNRESOLVED_CORRELATION_REASONS {
                return Err(QueryPostprocessingExhausted.into());
            }
            for reason in &correlation.difference_reasons {
                work.step(QueryPostprocessingStage::ReasonClone, is_cancelled)?;
                observed_difference_reasons.push(reason.clone());
            }
            if let Some(coverage) = self
                .phase_coverage
                .get(correlation.effective_profile_id.as_str())
            {
                if coverage.len() > MAX_GRAPH_PHASE_COVERAGE_ITEMS {
                    return Err(QueryPostprocessingExhausted.into());
                }
                for (phase, record) in *coverage {
                    work.step(QueryPostprocessingStage::PhaseEntryClone, is_cancelled)?;
                    let mut profile_ids = Vec::new();
                    for profile_id in &record.profile_ids {
                        work.step(QueryPostprocessingStage::PhaseProfileClone, is_cancelled)?;
                        profile_ids.push(profile_id.clone());
                    }
                    let mut completeness = Vec::new();
                    for value in &record.completeness {
                        work.step(
                            QueryPostprocessingStage::PhaseCompletenessClone,
                            is_cancelled,
                        )?;
                        completeness.push(value.clone());
                    }
                    phase_coverage.insert(
                        phase.clone(),
                        PhaseCoverageRecord {
                            profile_ids,
                            sites: record.sites,
                            edges: record.edges,
                            evidence: record.evidence,
                            resolved: record.resolved,
                            candidates: record.candidates,
                            external: record.external,
                            unresolved: record.unresolved,
                            completeness,
                        },
                    );
                }
            }
        }
        work.step(QueryPostprocessingStage::PathStep, is_cancelled)?;
        Ok(PathStep {
            edge: edge.clone(),
            condition_text: render_condition(&edge.condition),
            evidence: cloned_evidence,
            effective_profile_id: correlation
                .map(|correlation| correlation.effective_profile_id.clone()),
            correlation_status: correlation.map(|correlation| correlation.status.clone()),
            observed_difference_reasons,
            phase_coverage,
        })
    }
}

pub(crate) struct PathStepMaterializer<'a> {
    projection: PathStepProjection<'a>,
    work: QueryPostprocessingWork,
}

impl<'a> PathStepMaterializer<'a> {
    pub(crate) fn new<I>(
        snapshot: &'a GraphSnapshot,
        filter: &GraphQueryFilter,
        edges: I,
        maximum_work: usize,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = &'a EdgeRecord>,
    {
        let mut work = QueryPostprocessingWork::new(maximum_work);
        let mut selected_edge_ids = BTreeSet::new();
        for edge in edges {
            work.step(QueryPostprocessingStage::EdgeSelection, is_cancelled)?;
            selected_edge_ids.insert(edge.id.as_str());
        }
        let projection = PathStepProjection::build(
            snapshot,
            filter,
            &selected_edge_ids,
            &mut work,
            is_cancelled,
        )?;
        Ok(Self { projection, work })
    }

    pub(crate) fn materialize(
        &mut self,
        edge: &EdgeRecord,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<PathStep> {
        self.projection
            .materialize(edge, &mut self.work, is_cancelled)
    }

    pub(crate) fn clone_edge_output(
        &mut self,
        edge: &EdgeRecord,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<EdgeRecord> {
        self.work
            .step(QueryPostprocessingStage::EdgeOutput, is_cancelled)?;
        Ok(edge.clone())
    }
}

pub(crate) fn materialize_path_steps_bounded_cancellable(
    snapshot: &GraphSnapshot,
    filter: &GraphQueryFilter,
    edges: &[&EdgeRecord],
    maximum_work: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<PathStep>> {
    if edges.len() > crate::service_limits::MAX_DEPENDENCY_PATH_STEPS {
        return Err(QueryPostprocessingExhausted.into());
    }
    let mut materializer = PathStepMaterializer::new(
        snapshot,
        filter,
        edges.iter().copied(),
        maximum_work,
        is_cancelled,
    )?;
    let mut steps = Vec::with_capacity(edges.len());
    for edge in edges {
        steps.push(materializer.materialize(edge, is_cancelled)?);
    }
    Ok(steps)
}

fn evidence_order(left: &EvidenceRecord, right: &EvidenceRecord) -> std::cmp::Ordering {
    left.ordinal
        .cmp(&right.ordinal)
        .then(left.kind.cmp(&right.kind))
        .then(left.path.cmp(&right.path))
        .then(left.start_line.cmp(&right.start_line))
        .then(left.start_column.cmp(&right.start_column))
        .then(left.end_line.cmp(&right.end_line))
        .then(left.end_column.cmp(&right.end_column))
        .then(left.extractor.cmp(&right.extractor))
        .then(left.extractor_version.cmp(&right.extractor_version))
        .then(left.detail.cmp(&right.detail))
        .then_with(|| {
            left.properties
                .to_string()
                .cmp(&right.properties.to_string())
        })
}

fn site_correlation_map(matrix: &ProfileMatrixRecord) -> BTreeMap<&str, &ProfileCorrelationRecord> {
    matrix
        .correlations
        .iter()
        .flat_map(|correlation| {
            correlation
                .site_ids_by_phase
                .values()
                .flatten()
                .map(move |site_id| (site_id.as_str(), correlation))
        })
        .collect()
}

pub fn render_condition(value: &serde_json::Value) -> String {
    serde_json::from_value::<Condition>(value.clone())
        .map(|condition| condition.render())
        .unwrap_or_else(|_| value.to_string())
}

fn adjacency_cancellable<'a>(
    snapshot: &'a GraphSnapshot,
    reverse: bool,
    filter: &GraphQueryFilter,
    max_inspected_edges: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<(CanonicalAdjacency<'a>, bool)> {
    let mut ordered = BTreeMap::<&str, BTreeMap<(&str, &str), &EdgeRecord>>::new();
    for (inspected_edges, edge) in snapshot.edges.iter().enumerate() {
        if is_cancelled() {
            bail!("dependency traversal was cancelled");
        }
        if inspected_edges >= max_inspected_edges {
            return Ok((ordered, false));
        }
        if !filter.matches_edge(snapshot, edge) {
            continue;
        }
        let (key, next) = if reverse {
            (edge.target.as_str(), edge.source.as_str())
        } else {
            (edge.source.as_str(), edge.target.as_str())
        };
        ordered
            .entry(key)
            .or_default()
            .insert((next, edge.id.as_str()), edge);
    }
    if is_cancelled() {
        bail!("dependency traversal was cancelled");
    }
    Ok((ordered, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_store::{CoverageRecord, ScanRecord};
    use serde_json::json;

    fn node(id: &str, kind: &str, locator: &str, display_name: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: locator.to_owned(),
            display_name: display_name.to_owned(),
            properties: json!({}),
        }
    }

    fn evidence(owner_type: &str, owner_id: &str, ordinal: i64, path: &str) -> EvidenceRecord {
        EvidenceRecord {
            owner_type: owner_type.to_owned(),
            owner_id: owner_id.to_owned(),
            ordinal,
            kind: "semantic".to_owned(),
            extractor: "go-types".to_owned(),
            extractor_version: "1".to_owned(),
            path: path.to_owned(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
            detail: None,
            properties: json!({}),
        }
    }

    fn correlation(edge_ids: Vec<String>, reason_count: usize) -> ProfileCorrelationRecord {
        ProfileCorrelationRecord {
            id: "correlation:test".to_owned(),
            effective_profile_id: "effective:test".to_owned(),
            source: "a".to_owned(),
            kind: "imports".to_owned(),
            specifier: "b".to_owned(),
            status: "matched".to_owned(),
            condition_union: json!({"op":"all","conditions":[]}),
            conditions_by_phase: BTreeMap::new(),
            targets_by_phase: BTreeMap::new(),
            resolutions_by_phase: BTreeMap::new(),
            site_ids_by_phase: BTreeMap::new(),
            edge_ids_by_phase: BTreeMap::from([("semantic".to_owned(), edge_ids)]),
            difference_reasons: (0..reason_count)
                .map(|index| format!("reason-{index:03}"))
                .collect(),
            diagnostic_id: None,
        }
    }

    fn profile_entry(
        phase_count: usize,
        profile_ids_per_phase: usize,
        completeness_per_phase: usize,
    ) -> depgraph_store::ProfileMatrixEntryRecord {
        let mut phase_coverage = BTreeMap::new();
        for index in 0..phase_count {
            phase_coverage.insert(
                format!("phase-{index:03}"),
                PhaseCoverageRecord {
                    profile_ids: (0..profile_ids_per_phase)
                        .map(|item| format!("profile-{item:03}"))
                        .collect(),
                    completeness: (0..completeness_per_phase)
                        .map(|item| format!("complete-{item:03}"))
                        .collect(),
                    ..PhaseCoverageRecord::default()
                },
            );
        }
        depgraph_store::ProfileMatrixEntryRecord {
            id: "effective:test".to_owned(),
            effective_input_id: "effective-input:test".to_owned(),
            language: "rust".to_owned(),
            profile_ids: Vec::new(),
            parent_profile_ids: Vec::new(),
            phases: Vec::new(),
            condition_union: json!({"op":"all","conditions":[]}),
            phase_coverage,
            selection_reasons: Vec::new(),
            axis_conflicts: Vec::new(),
        }
    }

    fn snapshot() -> GraphSnapshot {
        let nodes = ["a", "b", "c"]
            .into_iter()
            .map(|id| NodeRecord {
                id: id.to_owned(),
                kind: "file".to_owned(),
                locator: format!("file://{id}"),
                display_name: id.to_owned(),
                properties: json!({}),
            })
            .collect();
        let edges = [("a", "b"), ("b", "c"), ("c", "a")]
            .into_iter()
            .enumerate()
            .map(|(index, (source, target))| EdgeRecord {
                id: format!("e{index}"),
                site_id: Some(format!("s{index}")),
                source: source.to_owned(),
                target: target.to_owned(),
                kind: "imports".to_owned(),
                phase: "syntax".to_owned(),
                environment: "any".to_owned(),
                profile_id: "test".to_owned(),
                resolution_status: "resolved".to_owned(),
                precision: "exact".to_owned(),
                condition: json!({"op":"all","conditions":[]}),
                generated: false,
            })
            .collect();
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan".to_owned(),
                root: "/tmp".to_owned(),
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
            nodes,
            sites: Vec::new(),
            edges,
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: depgraph_store::ProfileMatrixRecord::default(),
        }
    }

    #[test]
    fn adjacency_construction_is_cancellable_during_scanning() {
        let graph = snapshot();
        let mut checks = 0_usize;
        let error = adjacency_cancellable(
            &graph,
            false,
            &GraphQueryFilter::default(),
            usize::MAX,
            &mut || {
                checks += 1;
                checks > 1
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
    }

    #[test]
    fn adjacency_construction_is_cancellable_after_scanning() {
        let graph = snapshot();
        let mut checks = 0_usize;
        let error = adjacency_cancellable(
            &graph,
            false,
            &GraphQueryFilter::default(),
            usize::MAX,
            &mut || {
                checks += 1;
                checks > graph.edges.len()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
    }

    #[test]
    fn adjacency_construction_honors_its_independent_inspection_cap() -> Result<()> {
        let graph = snapshot();
        let (adjacency, complete) =
            adjacency_cancellable(&graph, false, &GraphQueryFilter::default(), 1, &mut || {
                false
            })?;
        assert!(!complete);
        assert_eq!(adjacency.values().map(BTreeMap::len).sum::<usize>(), 1);
        Ok(())
    }

    #[test]
    fn adjacency_scan_overflow_marks_the_complete_execution_fail_closed() -> Result<()> {
        let graph = snapshot();
        let execution = traverse_bounded_filtered_cancellable_with_adjacency_limit(
            &graph,
            "id:a",
            true,
            false,
            &GraphQueryFilter::default(),
            100,
            1,
            || false,
        )?;
        assert!(!execution.complete);
        assert_eq!(execution.result.steps.len(), 1);
        assert_eq!(execution.diagnostics.len(), 1);
        Ok(())
    }

    #[test]
    fn shortest_path_is_deterministic() -> Result<()> {
        let result = why(&snapshot(), "id:a", "id:c")?;
        assert!(result.path_found);
        assert_eq!(result.steps.len(), 2);
        assert_eq!(result.steps[0].edge.id, "e0");
        Ok(())
    }

    #[test]
    fn unreachable_nodes_are_a_deterministic_query_result() -> Result<()> {
        let mut disconnected = snapshot();
        disconnected.edges.clear();
        let result = why(&disconnected, "id:c", "id:a")?;
        assert!(!result.path_found);
        assert!(result.steps.is_empty());
        assert_eq!(result.from.id, "c");
        assert_eq!(result.to.id, "a");
        Ok(())
    }

    #[test]
    fn finds_representative_file_cycle() {
        let result = cycles(&snapshot(), CycleLevel::File);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node_ids.first(), result[0].node_ids.last());
    }

    #[test]
    fn semantic_selectors_only_match_their_node_kind() -> Result<()> {
        let mut graph = snapshot();
        let mut type_node = node(
            "type:sha256:222",
            "type",
            "example.com/module.Common",
            "Common",
        );
        type_node.properties = json!({
            "canonical_identity": {"resolver_identity": 42}
        });
        graph.nodes = vec![
            node(
                "symbol:sha256:111",
                "symbol",
                "example.com/module.Common",
                "Common",
            ),
            type_node,
            node("file:sha256:333", "file", "file://Common", "Common"),
        ];

        assert_eq!(
            resolve_selector(&graph, "symbol:Common")?.id,
            "symbol:sha256:111"
        );
        assert_eq!(
            resolve_selector(&graph, "type:Common")?.id,
            "type:sha256:222"
        );
        assert_eq!(
            resolve_selector(&graph, "id:symbol:sha256:111")?.kind,
            "symbol"
        );
        Ok(())
    }

    #[test]
    fn semantic_selector_prefers_exact_resolver_identity_over_locator_partial_matches() -> Result<()>
    {
        let mut graph = snapshot();
        let symbol_resolver = "example.com/semantic/model.InferredCall";
        let type_resolver = "example.com/semantic/model.GenericMatcher";
        let semantic_node = |id: &str, kind: &str, resolver: &str, display_name: &str| NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: format!("go-{kind}:{resolver}"),
            display_name: display_name.to_owned(),
            properties: json!({
                "language": "go",
                "package_locator": "go-package:example.com/semantic/model",
                "canonical_identity": {
                    "language": "go",
                    "package_locator": "go-package:example.com/semantic/model",
                    "identity_kind": "named",
                    "resolver_identity": resolver,
                }
            }),
        };
        graph.nodes = vec![
            semantic_node("symbol:origin", "symbol", symbol_resolver, "InferredCall"),
            semantic_node(
                "symbol:instance",
                "symbol",
                &format!("{symbol_resolver}[int]"),
                "InferredCall[int]",
            ),
            semantic_node("type:origin", "type", type_resolver, "GenericMatcher"),
            semantic_node(
                "type:instance",
                "type",
                &format!("{type_resolver}[string]"),
                "GenericMatcher[string]",
            ),
        ];

        assert_eq!(
            resolve_selector(&graph, &format!("symbol:{symbol_resolver}"))?.id,
            "symbol:origin"
        );
        assert_eq!(
            resolve_selector(&graph, &format!("type:{type_resolver}"))?.id,
            "type:origin"
        );
        Ok(())
    }

    #[test]
    fn legacy_selector_prefixes_remain_compatible() -> Result<()> {
        let mut graph = snapshot();
        let mut file = node("file:id", "file", "file://src/lib.rs", "lib.rs");
        file.properties = json!({"path": "src/lib.rs"});
        graph.nodes = vec![
            file,
            node("package:id", "package_instance", "pkg://demo", "demo"),
            node(
                "route:id",
                "route",
                "route:///products/$id",
                "/products/$id",
            ),
        ];

        assert_eq!(resolve_selector(&graph, "id:file:id")?.id, "file:id");
        assert_eq!(resolve_selector(&graph, "path:src/lib.rs")?.id, "file:id");
        assert_eq!(resolve_selector(&graph, "package:demo")?.id, "package:id");
        assert_eq!(
            resolve_selector(&graph, "route:/products/$id")?.id,
            "route:id"
        );
        Ok(())
    }

    #[test]
    fn ambiguous_selector_lists_stable_ids_in_deterministic_order() {
        let mut graph = snapshot();
        graph.nodes = vec![
            node("symbol:z", "symbol", "go://z.Shared", "Shared"),
            node("symbol:a", "symbol", "go://a.Shared", "Shared"),
        ];

        let message = resolve_selector(&graph, "symbol:Shared")
            .expect_err("selector must be ambiguous")
            .to_string();
        assert_eq!(
            message,
            "selector \"symbol:Shared\" is ambiguous; select a candidate with id:<stable-id>. candidates: go://a.Shared (symbol, id:symbol:a), go://z.Shared (symbol, id:symbol:z)"
        );
    }

    #[test]
    fn selector_resolution_is_incrementally_ordered_tightly_bounded_and_cancellable() {
        let node_count = 64_usize;
        let mut graph = snapshot();
        graph.nodes = (0..node_count)
            .rev()
            .map(|index| NodeRecord {
                id: format!("node:{index:04}"),
                kind: "file".to_owned(),
                locator: format!("repo://src/{index:04}.rs"),
                display_name: if index == node_count - 1 {
                    "unique-target".to_owned()
                } else {
                    format!("unrelated-{index:04}")
                },
                properties: json!({"path":format!("src/{index:04}.rs")}),
            })
            .collect();
        let exact_work = node_count + 2;
        let resolved =
            resolve_selector_bounded_cancellable(&graph, "unique-target", exact_work, &mut || {
                false
            })
            .expect("the exact selector work bound succeeds");
        assert_eq!(resolved.id, format!("node:{:04}", node_count - 1));

        let error = resolve_selector_bounded_cancellable(
            &graph,
            "unique-target",
            exact_work - 1,
            &mut || false,
        )
        .expect_err("one selector work item above the bound must fail closed");
        assert!(is_resource_exhausted(&error));

        let mut checks = 0_usize;
        let error = resolve_selector_bounded_cancellable(
            &graph,
            "id:does-not-match",
            exact_work,
            &mut || {
                checks += 1;
                checks >= 4
            },
        )
        .expect_err("cancellation during the node scan must return no selector");
        assert!(is_cancelled(&error));
        assert_eq!(checks, 4);

        for (index, node) in graph.nodes.iter_mut().take(3).enumerate() {
            node.id = ["node:c", "node:a", "node:b"][index].to_owned();
            node.display_name = "ambiguous-target".to_owned();
        }
        let error =
            resolve_selector_bounded_cancellable(&graph, "ambiguous-target", 1_000, &mut || false)
                .expect_err("ambiguous selector remains a domain error");
        assert!(!is_resource_exhausted(&error));
        assert!(!is_cancelled(&error));
        let message = error.to_string();
        let a = message.find("id:node:a").expect("candidate a");
        let b = message.find("id:node:b").expect("candidate b");
        let c = message.find("id:node:c").expect("candidate c");
        assert!(a < b && b < c, "ambiguous candidates remain ID-ordered");
    }

    #[test]
    fn traversal_steps_include_only_owned_edge_evidence_in_canonical_order() -> Result<()> {
        let mut graph = snapshot();
        graph.edges[0].phase = "semantic".to_owned();
        graph.evidence = vec![
            evidence("edge", "e0", 2, "second.go"),
            evidence("site", "e0", 0, "site.go"),
            evidence("edge", "e1", 0, "other-edge.go"),
            evidence("edge", "e0", 0, "first.go"),
        ];

        let deps = traverse(&graph, "id:a", false, false)?;
        assert_eq!(deps.edges.len(), 1);
        assert_eq!(deps.steps.len(), 1);
        assert_eq!(deps.steps[0].edge.id, "e0");
        assert_eq!(
            deps.steps[0]
                .evidence
                .iter()
                .map(|item| (item.ordinal, item.path.as_str()))
                .collect::<Vec<_>>(),
            vec![(0, "first.go"), (2, "second.go")]
        );

        let dependents = traverse(&graph, "id:b", false, true)?;
        assert_eq!(dependents.steps.len(), 1);
        assert_eq!(dependents.steps[0].edge.id, "e0");
        assert_eq!(dependents.steps[0].evidence.len(), 2);
        Ok(())
    }

    #[test]
    fn edge_evidence_materialization_accepts_exact_bound_and_rejects_one_over() -> Result<()> {
        let mut graph = snapshot();
        graph.evidence = (0..MAX_GRAPH_EVIDENCE_ITEMS)
            .map(|ordinal| evidence("edge", "e0", ordinal as i64, "src/a.rs"))
            .collect();
        let exact = traverse(&graph, "id:a", false, false)?;
        assert_eq!(exact.steps.len(), 1);
        assert_eq!(exact.steps[0].evidence.len(), MAX_GRAPH_EVIDENCE_ITEMS);

        graph.evidence.push(evidence(
            "edge",
            "e0",
            MAX_GRAPH_EVIDENCE_ITEMS as i64,
            "src/a.rs",
        ));
        let error = traverse(&graph, "id:a", false, false)
            .expect_err("evidence item 65 must reject the complete traversal");
        assert!(is_resource_exhausted(&error));

        let selected = BTreeSet::from(["e0"]);
        let mut work = QueryPostprocessingWork::with_stage_cancellation(
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
            QueryPostprocessingStage::EvidenceScan,
            3,
        );
        let error = PathStepProjection::build(
            &graph,
            &GraphQueryFilter::default(),
            &selected,
            &mut work,
            &mut || false,
        )
        .expect_err("cancellation during evidence aggregation must fail closed");
        assert!(is_cancelled(&error));
        assert_eq!(work.stage_count(QueryPostprocessingStage::EvidenceScan), 3);

        graph.evidence.truncate(2);
        let exact = materialize_path_steps_bounded_cancellable(
            &graph,
            &GraphQueryFilter::default(),
            &[&graph.edges[0]],
            14,
            &mut || false,
        )?;
        assert_eq!(exact[0].evidence.len(), 2);
        let error = materialize_path_steps_bounded_cancellable(
            &graph,
            &GraphQueryFilter::default(),
            &[&graph.edges[0]],
            13,
            &mut || false,
        )
        .expect_err("one less than the exact evidence postprocessing work must reject");
        assert!(is_resource_exhausted(&error));
        Ok(())
    }

    #[test]
    fn path_step_postprocessing_has_one_exact_cumulative_budget() -> Result<()> {
        let graph = snapshot();
        let selected = BTreeSet::from(["e0"]);
        let mut work = QueryPostprocessingWork::new(3);
        let projection = PathStepProjection::build(
            &graph,
            &GraphQueryFilter::default(),
            &selected,
            &mut work,
            &mut || false,
        )?;
        let step = projection.materialize(&graph.edges[0], &mut work, &mut || false)?;
        assert_eq!(step.edge.id, "e0");
        assert_eq!(work.used(), 3);

        let error = materialize_path_steps_bounded_cancellable(
            &graph,
            &GraphQueryFilter::default(),
            &[&graph.edges[0]],
            3,
            &mut || false,
        )
        .expect_err("one less than the exact four-step materialization work must reject");
        assert!(is_resource_exhausted(&error));
        let exact = materialize_path_steps_bounded_cancellable(
            &graph,
            &GraphQueryFilter::default(),
            &[&graph.edges[0]],
            4,
            &mut || false,
        )?;
        assert_eq!(exact.len(), 1);
        Ok(())
    }

    #[test]
    fn path_step_evidence_insertion_finalization_and_output_are_cancellable() {
        let mut graph = snapshot();
        graph.evidence = vec![
            evidence("edge", "e0", 2, "two.rs"),
            evidence("edge", "e0", 1, "one.rs"),
        ];
        let selected = BTreeSet::from(["e0"]);
        for (stage, completed, label) in [
            (
                QueryPostprocessingStage::EvidenceOwnerInsertion,
                1,
                "evidence insertion",
            ),
            (
                QueryPostprocessingStage::EvidenceOwnerFinalization,
                1,
                "evidence finalization",
            ),
            (
                QueryPostprocessingStage::EvidenceClone,
                1,
                "retained evidence clone",
            ),
        ] {
            let mut work = QueryPostprocessingWork::with_stage_cancellation(100, stage, completed);
            let error = PathStepProjection::build(
                &graph,
                &GraphQueryFilter::default(),
                &selected,
                &mut work,
                &mut || false,
            )
            .expect_err(label);
            assert!(is_cancelled(&error), "{label}");
            assert_eq!(work.stage_count(stage), completed);
        }

        for (stage, completed, label) in [
            (QueryPostprocessingStage::EdgeLookup, 0, "edge lookup"),
            (QueryPostprocessingStage::PathStep, 1, "path-step output"),
        ] {
            let mut work = QueryPostprocessingWork::with_stage_cancellation(100, stage, completed);
            let projection = PathStepProjection::build(
                &graph,
                &GraphQueryFilter::default(),
                &selected,
                &mut work,
                &mut || false,
            )
            .expect("projection builds before output cancellation");
            let error = projection
                .materialize(&graph.edges[0], &mut work, &mut || false)
                .expect_err(label);
            assert!(is_cancelled(&error), "{label}");
            assert_eq!(work.stage_count(stage), completed, "{label}");
        }
    }

    #[test]
    fn path_correlation_caps_and_single_phase_index_are_fail_closed() -> Result<()> {
        let mut graph = snapshot();
        graph.profile_matrix.correlations = vec![correlation(
            vec!["e0".to_owned(), "e1".to_owned()],
            MAX_UNRESOLVED_CORRELATION_REASONS,
        )];
        graph.profile_matrix.entries = vec![profile_entry(MAX_GRAPH_PHASE_COVERAGE_ITEMS, 0, 0)];
        let selected = BTreeSet::from(["e0", "e1"]);
        let mut work = QueryPostprocessingWork::new(10_000);
        let projection = PathStepProjection::build(
            &graph,
            &GraphQueryFilter::default(),
            &selected,
            &mut work,
            &mut || false,
        )?;
        let first = projection.materialize(&graph.edges[0], &mut work, &mut || false)?;
        let second = projection.materialize(&graph.edges[1], &mut work, &mut || false)?;
        assert_eq!(
            first.observed_difference_reasons.len(),
            MAX_UNRESOLVED_CORRELATION_REASONS
        );
        assert_eq!(first.phase_coverage.len(), MAX_GRAPH_PHASE_COVERAGE_ITEMS);
        assert_eq!(second.phase_coverage, first.phase_coverage);
        assert_eq!(
            work.stage_count(QueryPostprocessingStage::ProfileEntry),
            1,
            "the profile matrix is indexed once for the complete path"
        );

        graph.profile_matrix.correlations[0]
            .difference_reasons
            .push("one-over".to_owned());
        let error = materialize_path_steps_bounded_cancellable(
            &graph,
            &GraphQueryFilter::default(),
            &[&graph.edges[0]],
            10_000,
            &mut || false,
        )
        .expect_err("reason 17 must reject the complete path");
        assert!(is_resource_exhausted(&error));

        graph.profile_matrix.correlations[0]
            .difference_reasons
            .pop();
        graph.profile_matrix.entries[0]
            .phase_coverage
            .insert("phase-over".to_owned(), PhaseCoverageRecord::default());
        let error = materialize_path_steps_bounded_cancellable(
            &graph,
            &GraphQueryFilter::default(),
            &[&graph.edges[0]],
            10_000,
            &mut || false,
        )
        .expect_err("phase coverage item 65 must reject the complete path");
        assert!(is_resource_exhausted(&error));
        Ok(())
    }

    #[test]
    fn path_correlation_nested_scans_and_clones_are_cancellable_without_partial_steps() {
        let mut graph = snapshot();
        let mut nested_ids = (0..8)
            .map(|index| format!("unselected:{index}"))
            .collect::<Vec<_>>();
        nested_ids.push("e0".to_owned());
        graph.profile_matrix.correlations =
            vec![correlation(nested_ids, MAX_UNRESOLVED_CORRELATION_REASONS)];
        graph.profile_matrix.entries = vec![profile_entry(2, 4, 4)];
        let selected = BTreeSet::from(["e0"]);

        for (stage, completed, label) in [
            (
                QueryPostprocessingStage::CorrelationPhase,
                0,
                "correlation phase scan",
            ),
            (
                QueryPostprocessingStage::CorrelationEdge,
                3,
                "nested edge expansion",
            ),
            (
                QueryPostprocessingStage::CorrelationInsertion,
                0,
                "edge correlation insertion",
            ),
            (
                QueryPostprocessingStage::ProfileEntry,
                0,
                "phase index scan",
            ),
            (
                QueryPostprocessingStage::ProfileInsertion,
                0,
                "phase index insertion",
            ),
        ] {
            let mut work =
                QueryPostprocessingWork::with_stage_cancellation(1_000, stage, completed);
            let error = PathStepProjection::build(
                &graph,
                &GraphQueryFilter::default(),
                &selected,
                &mut work,
                &mut || false,
            )
            .expect_err(label);
            assert!(is_cancelled(&error), "{label}");
            assert_eq!(work.stage_count(stage), completed, "{label}");
        }

        for (stage, completed, label) in [
            (QueryPostprocessingStage::ReasonClone, 3, "reason clone"),
            (
                QueryPostprocessingStage::PhaseEntryClone,
                1,
                "phase entry clone",
            ),
            (
                QueryPostprocessingStage::PhaseProfileClone,
                2,
                "profile ID clone",
            ),
            (
                QueryPostprocessingStage::PhaseCompletenessClone,
                2,
                "completeness clone",
            ),
        ] {
            let mut work =
                QueryPostprocessingWork::with_stage_cancellation(1_000, stage, completed);
            let projection = PathStepProjection::build(
                &graph,
                &GraphQueryFilter::default(),
                &selected,
                &mut work,
                &mut || false,
            )
            .expect("projection builds before clone cancellation");
            let error = projection
                .materialize(&graph.edges[0], &mut work, &mut || false)
                .expect_err(label);
            assert!(is_cancelled(&error), "{label}");
            assert_eq!(work.stage_count(stage), completed, "{label}");
        }
    }

    #[test]
    fn duplicate_selected_edge_correlation_is_integrity() {
        let mut graph = snapshot();
        graph.profile_matrix.correlations =
            vec![correlation(vec!["e0".to_owned(), "e0".to_owned()], 0)];
        let error = materialize_path_steps_bounded_cancellable(
            &graph,
            &GraphQueryFilter::default(),
            &[&graph.edges[0]],
            100,
            &mut || false,
        )
        .expect_err("duplicate edge correlation mapping must fail closed");
        assert!(is_integrity(&error));
    }

    #[test]
    fn interactive_pages_are_canonical_bounded_and_lossless() -> Result<()> {
        let graph = snapshot();
        let traversal = traverse_bounded_filtered(
            &graph,
            "id:a",
            true,
            false,
            &GraphQueryFilter::default(),
            100,
        )?;
        assert!(traversal.complete);
        let summary = traversal_summary(&traversal.result);
        let context = json!({"selector":"id:a","transitive":true,"reverse":false});
        let mut cursor = None;
        let mut observed = Vec::new();
        loop {
            let page = paginate_interactive_query(
                &traversal.result.steps,
                summary.clone(),
                InteractiveQueryPageRequest {
                    command: "deps",
                    scan_id: "scan",
                    snapshot_id: "snapshot:scan",
                    context: &context,
                    cursor: cursor.as_deref(),
                    max_items: 1,
                    max_bytes: 64 * 1024,
                    traversal_complete: traversal.complete,
                    traversed_items: traversal.traversed_edges,
                    root: Some(&traversal.result.root),
                    diagnostics: traversal.diagnostics.clone(),
                },
            )?;
            assert_eq!(
                usize::try_from(page.serialized_output_bytes).unwrap(),
                canonical_json(&serde_json::to_value(&page)?).len()
            );
            assert!(usize::try_from(page.serialized_output_bytes).unwrap() <= 64 * 1024);
            observed.extend(page.items.iter().map(|step| step.edge.id.clone()));
            if page.complete {
                assert!(page.next_cursor.is_none());
                break;
            }
            assert_eq!(
                page.diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "QUERY_OUTPUT_TRUNCATED")
                    .count(),
                1
            );
            cursor = page.next_cursor;
        }
        assert_eq!(
            observed,
            traversal
                .result
                .steps
                .iter()
                .map(|step| step.edge.id.clone())
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn complete_final_page_is_admitted_when_partial_page_metadata_is_larger() -> Result<()> {
        let graph = snapshot();
        let items = vec!["a".to_owned(), "b".to_owned()];
        let summary = summarize_query_items(
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
            items.len(),
        );
        let context = json!({"selector":"id:a","final_page_boundary":true});
        let mut root = graph.nodes[0].clone();
        root.properties = json!({"padding":"x".repeat(4 * 1024)});
        let request = |max_bytes| InteractiveQueryPageRequest {
            command: "deps",
            scan_id: "scan",
            snapshot_id: "snapshot:scan",
            context: &context,
            cursor: None,
            max_items: items.len(),
            max_bytes,
            traversal_complete: true,
            traversed_items: 2,
            root: Some(&root),
            diagnostics: Vec::new(),
        };
        let unconstrained = paginate_interactive_query(
            &items,
            summary.clone(),
            request(MAX_INTERACTIVE_QUERY_BYTES),
        )?;
        assert!(unconstrained.complete);
        let exact_budget = usize::try_from(unconstrained.serialized_output_bytes)?;
        let page = paginate_interactive_query(&items, summary, request(exact_budget))?;
        assert!(page.complete);
        assert_eq!(page.items, items);
        assert_eq!(page.serialized_output_bytes, exact_budget as u64);
        Ok(())
    }

    #[test]
    fn large_bounded_fixture_pages_without_duplicates_or_gaps() -> Result<()> {
        let mut graph = snapshot();
        graph.nodes = (0..=512)
            .map(|index| {
                node(
                    &format!("node:{index:04}"),
                    "file",
                    &format!("file://{index:04}"),
                    &format!("{index:04}"),
                )
            })
            .collect();
        graph.edges = (0..512)
            .map(|index| EdgeRecord {
                id: format!("edge:{index:04}"),
                site_id: Some(format!("site:{index:04}")),
                source: format!("node:{index:04}"),
                target: format!("node:{:04}", index + 1),
                kind: "imports".to_owned(),
                phase: if index % 2 == 0 {
                    "static".to_owned()
                } else {
                    "semantic".to_owned()
                },
                environment: "host".to_owned(),
                profile_id: format!("fixture:{}", index % 4),
                resolution_status: "resolved".to_owned(),
                precision: "exact".to_owned(),
                condition: json!({"op":"all","conditions":[]}),
                generated: false,
            })
            .collect();
        graph.evidence = graph
            .edges
            .iter()
            .map(|edge| {
                let mut item = evidence("edge", &edge.id, 0, "src/large.rs");
                item.properties = json!({"bounded_fixture":"x".repeat(128)});
                item
            })
            .collect();
        let traversal = traverse_bounded_filtered(
            &graph,
            "id:node:0000",
            true,
            false,
            &GraphQueryFilter::default(),
            1_000,
        )?;
        assert!(traversal.complete);
        assert_eq!(traversal.result.steps.len(), 512);
        let summary = traversal_summary(&traversal.result);
        let context = json!({"selector":"id:node:0000","fixture":"large"});
        let mut cursor = None;
        let mut observed = Vec::new();
        loop {
            let page = paginate_interactive_query(
                &traversal.result.steps,
                summary.clone(),
                InteractiveQueryPageRequest {
                    command: "deps",
                    scan_id: "scan-large",
                    snapshot_id: "snapshot:scan-large",
                    context: &context,
                    cursor: cursor.as_deref(),
                    max_items: 17,
                    max_bytes: 16 * 1024,
                    traversal_complete: true,
                    traversed_items: traversal.traversed_edges,
                    root: Some(&traversal.result.root),
                    diagnostics: Vec::new(),
                },
            )?;
            assert!(page.serialized_output_bytes <= 16 * 1024);
            observed.extend(page.items.iter().map(|step| step.edge.id.clone()));
            cursor = page.next_cursor;
            if page.complete {
                break;
            }
        }
        assert_eq!(observed.len(), 512);
        assert_eq!(
            observed.iter().collect::<BTreeSet<_>>().len(),
            observed.len()
        );
        assert_eq!(
            observed,
            traversal
                .result
                .steps
                .iter()
                .map(|step| step.edge.id.clone())
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn interactive_cursor_and_traversal_limits_fail_closed() -> Result<()> {
        let graph = snapshot();
        let traversal = traverse_bounded_filtered(
            &graph,
            "id:a",
            true,
            false,
            &GraphQueryFilter::default(),
            1,
        )?;
        assert!(!traversal.complete);
        assert_eq!(traversal.traversed_edges, 1);
        assert_eq!(
            traversal.diagnostics[0].code,
            "QUERY_TRAVERSAL_LIMIT_REACHED"
        );

        let context = json!({"selector":"id:a"});
        let first = paginate_interactive_query(
            &traversal.result.steps,
            traversal_summary(&traversal.result),
            InteractiveQueryPageRequest {
                command: "deps",
                scan_id: "scan",
                snapshot_id: "snapshot:scan",
                context: &context,
                cursor: None,
                max_items: 1,
                max_bytes: 64 * 1024,
                traversal_complete: traversal.complete,
                traversed_items: traversal.traversed_edges,
                root: Some(&traversal.result.root),
                diagnostics: traversal.diagnostics,
            },
        )?;
        assert!(!first.complete);
        assert!(first.next_cursor.is_none());
        let error = paginate_interactive_query(
            &first.items,
            first.summary.clone(),
            InteractiveQueryPageRequest {
                command: "deps",
                scan_id: "other-scan",
                snapshot_id: "snapshot:other-scan",
                context: &context,
                cursor: Some("depgraph-query-cursor-v1.1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                max_items: 1,
                max_bytes: 64 * 1024,
                traversal_complete: true,
                traversed_items: 1,
                root: None,
                diagnostics: Vec::new(),
            },
        )
        .expect_err("tampered cursor must fail");
        assert!(
            error
                .to_string()
                .contains("cursor does not match this snapshot and query")
        );
        Ok(())
    }

    #[test]
    fn interactive_cursor_is_bound_to_the_immutable_snapshot_identity() -> Result<()> {
        let items = vec!["first".to_owned(), "second".to_owned()];
        let summary = summarize_query_items(
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
            items.len(),
        );
        let context = json!({"selector":"id:a"});
        let first = paginate_interactive_query(
            &items,
            summary.clone(),
            InteractiveQueryPageRequest {
                command: "deps",
                scan_id: "scan",
                snapshot_id: "snapshot:before-build",
                context: &context,
                cursor: None,
                max_items: 1,
                max_bytes: 64 * 1024,
                traversal_complete: true,
                traversed_items: 2,
                root: None,
                diagnostics: Vec::new(),
            },
        )?;
        let cursor = first.next_cursor.context("first page cursor")?;
        let error = paginate_interactive_query(
            &items,
            summary,
            InteractiveQueryPageRequest {
                command: "deps",
                scan_id: "scan",
                snapshot_id: "snapshot:after-build",
                context: &context,
                cursor: Some(&cursor),
                max_items: 1,
                max_bytes: 64 * 1024,
                traversal_complete: true,
                traversed_items: 2,
                root: None,
                diagnostics: Vec::new(),
            },
        )
        .expect_err("a cursor from another immutable snapshot must fail");
        assert!(
            error
                .to_string()
                .contains("cursor does not match this snapshot and query")
        );
        Ok(())
    }

    #[test]
    fn oversized_next_item_returns_a_stable_byte_budget_diagnostic() -> Result<()> {
        let mut graph = snapshot();
        graph.evidence.push(EvidenceRecord {
            properties: json!({"large":"x".repeat(8 * 1024)}),
            ..evidence("edge", "e0", 0, "large.go")
        });
        let traversal = traverse(&graph, "id:a", false, false)?;
        let context = json!({"selector":"id:a"});
        let page = paginate_interactive_query(
            &traversal.steps,
            traversal_summary(&traversal),
            InteractiveQueryPageRequest {
                command: "deps",
                scan_id: "scan",
                snapshot_id: "snapshot:scan",
                context: &context,
                cursor: None,
                max_items: 1,
                max_bytes: 4 * 1024,
                traversal_complete: true,
                traversed_items: 1,
                root: Some(&traversal.root),
                diagnostics: Vec::new(),
            },
        )?;
        assert!(!page.complete);
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
        assert_eq!(page.diagnostics[0].code, "QUERY_ITEM_EXCEEDS_BYTE_BUDGET");
        assert!(page.serialized_output_bytes <= 4 * 1024);
        Ok(())
    }

    #[test]
    fn diagnostic_filters_match_source_session_phase_profile_and_environment() -> Result<()> {
        let diagnostic = DiagnosticRecord {
            ordinal: 0,
            id: "diagnostic:runtime".to_owned(),
            severity: "warning".to_owned(),
            code: "RUNTIME_TARGET_UNMATCHED".to_owned(),
            message: "unmatched".to_owned(),
            path: None,
            adapter: Some("runtime-trace".to_owned()),
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            properties: json!({
                "session_id":"runtime-session:stable",
                "source_session_id":"collector-session",
                "phase":"runtime",
                "profile_id":"profile:runtime",
                "environment":{
                    "name":"production",
                    "runtime":"nodejs-24",
                    "region":"test-region-1"
                }
            }),
        };
        let matching = GraphQueryFilter::new(
            vec!["runtime".to_owned()],
            vec!["profile:runtime".to_owned()],
            vec!["collector-session".to_owned()],
            vec!["nodejs-24".to_owned()],
        )?;
        assert!(matching.matches_diagnostic(&diagnostic));
        assert!(
            !GraphQueryFilter::new(vec!["build".to_owned()], Vec::new(), Vec::new(), Vec::new())?
                .matches_diagnostic(&diagnostic)
        );
        assert!(
            !GraphQueryFilter::new(
                Vec::new(),
                Vec::new(),
                vec!["another-session".to_owned()],
                Vec::new()
            )?
            .matches_diagnostic(&diagnostic)
        );
        Ok(())
    }

    #[test]
    fn environment_filter_is_scoped_to_runtime_evidence_context() -> Result<()> {
        let mut graph = snapshot();
        graph.edges[0].environment = "production".to_owned();
        let filter = GraphQueryFilter::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec!["production".to_owned()],
        )?;
        assert!(!filter.matches_edge(&graph, &graph.edges[0]));

        graph.edges[0].phase = "runtime".to_owned();
        assert!(!filter.matches_edge(&graph, &graph.edges[0]));
        let mut runtime_evidence = evidence("edge", "e0", 0, "");
        runtime_evidence.kind = "runtime".to_owned();
        runtime_evidence.properties = json!({
            "session_id":"runtime-session",
            "source_session_id":"collector-session",
            "environment":{"name":"production"}
        });
        graph.evidence.push(runtime_evidence);
        assert!(filter.matches_edge(&graph, &graph.edges[0]));
        Ok(())
    }

    #[test]
    fn representative_symbol_cycle_is_deterministic() {
        let mut graph = snapshot();
        for node in &mut graph.nodes {
            node.kind = "symbol".to_owned();
        }
        let expected_node_ids = vec![
            "a".to_owned(),
            "b".to_owned(),
            "c".to_owned(),
            "a".to_owned(),
        ];

        let first = cycles(&graph, CycleLevel::Symbol);
        graph.edges.reverse();
        let reversed = cycles(&graph, CycleLevel::Symbol);

        assert_eq!(first[0].level, "symbol");
        assert_eq!(first[0].node_ids, expected_node_ids);
        assert_eq!(reversed[0].node_ids, expected_node_ids);
    }

    #[test]
    fn topology_projection_preserves_cycle_results() {
        let graph = snapshot();
        let topology = GraphTopology {
            nodes: graph
                .nodes
                .iter()
                .map(|node| depgraph_store::GraphTopologyNode {
                    id: node.id.clone(),
                    kind: node.kind.clone(),
                })
                .collect(),
            edges: graph
                .edges
                .iter()
                .map(|edge| depgraph_store::GraphTopologyEdge {
                    source: edge.source.clone(),
                    target: edge.target.clone(),
                })
                .collect(),
        };

        assert_eq!(
            serde_json::to_value(cycles(&graph, CycleLevel::File)).unwrap(),
            serde_json::to_value(cycles_from_topology(&topology, CycleLevel::File)).unwrap()
        );
    }
}
