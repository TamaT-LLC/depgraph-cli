use std::collections::{BTreeMap, HashMap, VecDeque};

use depgraph_store::{GraphSnapshot, NodeRecord};
use serde_json::json;

use super::contract::BASIS_POINTS_MAX;
use super::{
    BlockerKind, FindingBlocker, FindingIdentity, FindingKind, HealthFinding, Remediation,
    SourceLocation, finish_finding, rank_normalize_basis_points,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotspotWeights {
    pub fan_in: u32,
    pub fan_out: u32,
    pub reverse_impact: u32,
    pub git_churn: u32,
    pub runtime: u32,
}

/// Node kinds the hotspot analyzer scores. Result filters (`node_kinds`)
/// accept exactly this closed set so CLI and MCP share one vocabulary.
pub const HOTSPOT_SUBJECT_KINDS: [&str; 5] = ["file", "module", "symbol", "type", "route"];

#[must_use]
pub fn is_hotspot_subject_kind(kind: &str) -> bool {
    HOTSPOT_SUBJECT_KINDS.contains(&kind)
}

pub const DEFAULT_HOTSPOT_WEIGHTS: HotspotWeights = HotspotWeights {
    fan_in: 2_500,
    fan_out: 1_500,
    reverse_impact: 2_500,
    git_churn: 2_000,
    runtime: 1_500,
};

impl HotspotWeights {
    pub fn try_new(
        fan_in: u32,
        fan_out: u32,
        reverse_impact: u32,
        git_churn: u32,
        runtime: u32,
    ) -> Result<Self, &'static str> {
        let weights = Self {
            fan_in,
            fan_out,
            reverse_impact,
            git_churn,
            runtime,
        };
        weights.validate()?;
        Ok(weights)
    }

    pub(crate) fn validate(self) -> Result<(), &'static str> {
        if [
            self.fan_in,
            self.fan_out,
            self.reverse_impact,
            self.git_churn,
            self.runtime,
        ]
        .into_iter()
        .any(|weight| weight > BASIS_POINTS_MAX)
        {
            return Err("hotspot weight exceeds 10000");
        }
        if self.sum() > BASIS_POINTS_MAX {
            return Err("hotspot weights sum exceeds 10000");
        }
        Ok(())
    }

    #[must_use]
    pub const fn sum(self) -> u32 {
        self.fan_in
            .saturating_add(self.fan_out)
            .saturating_add(self.reverse_impact)
            .saturating_add(self.git_churn)
            .saturating_add(self.runtime)
    }

    #[must_use]
    pub fn as_map(self) -> BTreeMap<String, u32> {
        BTreeMap::from([
            ("fan_in".to_owned(), self.fan_in),
            ("fan_out".to_owned(), self.fan_out),
            ("reverse_impact".to_owned(), self.reverse_impact),
            ("git_churn".to_owned(), self.git_churn),
            ("runtime".to_owned(), self.runtime),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotspotLayer {
    FanIn,
    FanOut,
    ReverseImpact,
    GitChurn,
    Runtime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HotspotLayerScores {
    pub fan_in: u32,
    pub fan_out: u32,
    pub reverse_impact: u32,
    pub git_churn: u32,
    pub runtime: u32,
    pub total: u32,
}

/// The machine-readable contribution of one hotspot score layer.
///
/// `raw` is the source metric before rank normalization. Both basis-point
/// fields are bounded to `0..=10_000`; `weight_basis_points` is the configured
/// request weight and is deliberately retained when `available` is false so
/// consumers can explain why the layer contributed zero without renormalizing
/// the remaining layers.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct HotspotLayerScore {
    pub raw: u64,
    pub normalized_basis_points: u32,
    pub weight_basis_points: u32,
    pub available: bool,
}

/// Structured explainability data attached to a hotspot `HealthFinding`.
///
/// The field names are part of `depgraph-health-finding-v1`. Keep the existing
/// [`HotspotLayerScores`] aggregate type for callers that use the historical
/// normalized-only API; this type is the additive finding contract.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct HotspotFindingScores {
    pub fan_in: HotspotLayerScore,
    pub fan_out: HotspotLayerScore,
    pub reverse_impact: HotspotLayerScore,
    pub git_churn: HotspotLayerScore,
    pub runtime: HotspotLayerScore,
    pub total: u32,
}

/// Backwards-compatible short name for structured hotspot score data.
pub type HotspotScores = HotspotFindingScores;

#[derive(Clone, Debug, Default)]
pub struct HotspotLayerAvailability {
    pub churn: bool,
    pub runtime: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HotspotAnalysisError {
    #[error("hotspot weights are invalid")]
    InvalidInput,
    #[error("hotspot analysis was cancelled")]
    Cancelled,
    #[error("hotspot analysis exhausted its bounded work budget")]
    ResourceExhausted,
    /// More hotspot subjects than the response may carry as findings.
    #[error("hotspot analysis exceeded its subject limit")]
    SubjectLimit,
}

#[must_use = "hotspot analysis results must be handled"]
pub fn score_hotspots(
    snapshot: &GraphSnapshot,
    weights: HotspotWeights,
    churn: &BTreeMap<String, u64>,
    runtime: &BTreeMap<String, u64>,
    availability: HotspotLayerAvailability,
) -> Result<Vec<HealthFinding>, HotspotAnalysisError> {
    score_hotspots_cancellable(
        snapshot,
        weights,
        churn,
        runtime,
        availability,
        usize::MAX,
        usize::MAX,
        || false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn score_hotspots_cancellable(
    snapshot: &GraphSnapshot,
    weights: HotspotWeights,
    churn: &BTreeMap<String, u64>,
    runtime: &BTreeMap<String, u64>,
    availability: HotspotLayerAvailability,
    maximum_subjects: usize,
    maximum_work: usize,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<Vec<HealthFinding>, HotspotAnalysisError> {
    weights
        .validate()
        .map_err(|_| HotspotAnalysisError::InvalidInput)?;
    let mut work = HotspotWork::new(maximum_work);
    let mut subjects = Vec::new();
    for node in &snapshot.nodes {
        work.step(&mut is_cancelled)?;
        if is_hotspot_subject_kind(&node.kind) {
            if subjects.len() >= maximum_subjects {
                return Err(HotspotAnalysisError::SubjectLimit);
            }
            subjects.push(node);
        }
    }
    let graph = HotspotGraph::build(snapshot, &subjects, &mut work, &mut is_cancelled)?;
    let reverse = graph.reverse_impact_sizes(&subjects, &mut work, &mut is_cancelled)?;
    let mut fan_in = Vec::with_capacity(subjects.len());
    let mut fan_out = Vec::with_capacity(subjects.len());
    let mut churn_values = Vec::with_capacity(subjects.len());
    let mut runtime_values = Vec::with_capacity(subjects.len());
    for (position, node) in subjects.iter().enumerate() {
        work.step(&mut is_cancelled)?;
        let subject = graph.subject_vertices[position];
        fan_in.push(graph.fan_in[subject]);
        fan_out.push(graph.fan_out[subject]);
        churn_values.push(if availability.churn {
            churn_value(node, churn)
        } else {
            0
        });
        runtime_values.push(if availability.runtime {
            runtime.get(&node.id).copied().unwrap_or(0)
        } else {
            0
        });
    }
    if subjects.is_empty() {
        return Ok(Vec::new());
    }
    let fan_in_n = rank_normalize_basis_points(&fan_in);
    let fan_out_n = rank_normalize_basis_points(&fan_out);
    let reverse_n = rank_normalize_basis_points(&reverse);
    let churn_n = rank_normalize_basis_points(&churn_values);
    let runtime_n = rank_normalize_basis_points(&runtime_values);
    let mut scored = subjects
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            let scores = HotspotLayerScores {
                fan_in: fan_in_n[index],
                fan_out: fan_out_n[index],
                reverse_impact: reverse_n[index],
                git_churn: churn_n[index],
                runtime: runtime_n[index],
                total: hotspot_weighted_total([
                    (fan_in_n[index], weights.fan_in),
                    (fan_out_n[index], weights.fan_out),
                    (reverse_n[index], weights.reverse_impact),
                    (churn_n[index], weights.git_churn),
                    (runtime_n[index], weights.runtime),
                ]),
            };
            (
                node,
                scores,
                [
                    fan_in[index],
                    fan_out[index],
                    reverse[index],
                    churn_values[index],
                    runtime_values[index],
                ],
            )
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| {
        right
            .1
            .total
            .cmp(&left.1.total)
            .then_with(|| left.0.id.cmp(&right.0.id))
    });
    let mut findings = Vec::with_capacity(scored.len());
    for (node, scores, raw) in scored {
        work.step(&mut is_cancelled)?;
        let mut blockers = Vec::new();
        if !availability.churn {
            blockers.push(FindingBlocker {
                kind: BlockerKind::ChurnUnavailable,
                detail: "git churn was not available; layer contributed 0".to_owned(),
            });
        }
        if !availability.runtime {
            blockers.push(FindingBlocker {
                kind: BlockerKind::RuntimeNotObserved,
                detail: "runtime observation was not available; layer contributed 0".to_owned(),
            });
        }
        let location = node_path(node).map(|path| SourceLocation {
            path,
            start_line: super::unused::span_position(node, "start_line"),
            start_column: super::unused::span_position(node, "start_column"),
            end_line: super::unused::span_position(node, "end_line"),
            end_column: super::unused::span_position(node, "end_column"),
        });
        let hotspot_scores = HotspotFindingScores {
            fan_in: HotspotLayerScore {
                raw: raw[0],
                normalized_basis_points: scores.fan_in,
                weight_basis_points: weights.fan_in,
                available: true,
            },
            fan_out: HotspotLayerScore {
                raw: raw[1],
                normalized_basis_points: scores.fan_out,
                weight_basis_points: weights.fan_out,
                available: true,
            },
            reverse_impact: HotspotLayerScore {
                raw: raw[2],
                normalized_basis_points: scores.reverse_impact,
                weight_basis_points: weights.reverse_impact,
                available: true,
            },
            git_churn: HotspotLayerScore {
                raw: raw[3],
                normalized_basis_points: scores.git_churn,
                weight_basis_points: weights.git_churn,
                available: availability.churn,
            },
            runtime: HotspotLayerScore {
                raw: raw[4],
                normalized_basis_points: scores.runtime,
                weight_basis_points: weights.runtime,
                available: availability.runtime,
            },
            total: scores.total,
        };
        let mut finding = finish_finding(
            FindingIdentity {
                kind: FindingKind::Hotspot,
                subject_id: node.id.clone(),
                profile_scope: None,
                witness_key: json!({
                    "subject_id": node.id,
                    "weights": weights.as_map()
                }),
            },
            node.kind.clone(),
            location,
            format!(
                "hotspot score {}; normalized-bp fan-in={} fan-out={} reverse-impact={} git-churn={} runtime={}; raw fan-in={} fan-out={} reverse-impact={} git-churn={} runtime={}",
                scores.total,
                scores.fan_in,
                scores.fan_out,
                scores.reverse_impact,
                scores.git_churn,
                scores.runtime,
                raw[0],
                raw[1],
                raw[2],
                raw[3],
                raw[4],
            ),
            blockers,
            Vec::new(),
            vec![Remediation {
                kind: "use-health-hotspots".to_owned(),
                detail: "inspect layer evidence before treating rank as a deletion signal"
                    .to_owned(),
            }],
            Vec::new(),
            false,
            false,
        );
        finding.hotspot_scores = Some(hotspot_scores);
        finding.fingerprint = super::finding_fingerprint(&finding);
        findings.push(finding);
    }
    Ok(findings)
}

fn churn_value(node: &NodeRecord, churn: &BTreeMap<String, u64>) -> u64 {
    churn
        .get(&node.id)
        .copied()
        .or_else(|| node_path(node).and_then(|path| churn.get(path.as_str()).copied()))
        .unwrap_or(0)
}

fn node_path(node: &NodeRecord) -> Option<String> {
    let path = ["path", "source_path", "relative_path", "manifest_path"]
        .into_iter()
        .find_map(|key| node.properties.get(key).and_then(serde_json::Value::as_str))?;
    crate::service::RepositoryRelativePath::parse(path)
        .ok()
        .map(|path| path.as_str().to_owned())
}

/// 64-bit words in one [`LaneMask`].
const LANE_MASK_WORDS: usize = 4;

/// Subjects whose reverse reachability is computed together, one bit each.
///
/// 256 rather than 64 lanes roughly halves the reverse-impact work on the
/// Rust HIR snapshot of #590, whose parameters, locals, and closures share
/// most of their dependents with the enclosing function.
const REVERSE_IMPACT_LANES: usize = LANE_MASK_WORDS * u64::BITS as usize;

/// One bit per subject lane of a reverse-impact batch.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct LaneMask([u64; LANE_MASK_WORDS]);

impl LaneMask {
    fn is_empty(self) -> bool {
        self.0.iter().all(|word| *word == 0)
    }

    fn set(&mut self, lane: usize) {
        self.0[lane / u64::BITS as usize] |= 1_u64 << (lane % u64::BITS as usize);
    }

    fn union(self, other: Self) -> Self {
        let mut words = self.0;
        for (word, other) in words.iter_mut().zip(other.0) {
            *word |= other;
        }
        Self(words)
    }

    /// Call `visit` with every lane whose bit is set.
    fn for_each_lane(self, mut visit: impl FnMut(usize)) {
        for (index, mut word) in self.0.into_iter().enumerate() {
            while word != 0 {
                visit(index * u64::BITS as usize + word.trailing_zeros() as usize);
                word &= word - 1;
            }
        }
    }
}

/// Interned view of the snapshot edges used by the fan and reverse-impact
/// layers.
///
/// Vertices are every subject plus every edge endpoint, so an endpoint
/// without a node record still counts toward reverse impact. Subjects are
/// interned first; `fan_in` / `fan_out` count every edge (duplicates
/// included), while the reverse adjacency keeps each distinct
/// `target -> source` pair once because reachability does not depend on
/// edge multiplicity.
struct HotspotGraph {
    subject_vertices: Vec<usize>,
    fan_in: Vec<u64>,
    fan_out: Vec<u64>,
    dependents_start: Vec<usize>,
    dependents: Vec<usize>,
}

impl HotspotGraph {
    fn build(
        snapshot: &GraphSnapshot,
        subjects: &[&NodeRecord],
        work: &mut HotspotWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self, HotspotAnalysisError> {
        let mut vertices = HashMap::<&str, usize>::with_capacity(subjects.len());
        let mut subject_vertices = Vec::with_capacity(subjects.len());
        for node in subjects {
            work.step(is_cancelled)?;
            let next = vertices.len();
            subject_vertices.push(*vertices.entry(node.id.as_str()).or_insert(next));
        }
        let distinct_subjects = vertices.len();
        let mut fan_in = vec![0_u64; distinct_subjects];
        let mut fan_out = vec![0_u64; distinct_subjects];
        let mut pairs = Vec::with_capacity(snapshot.edges.len());
        for edge in &snapshot.edges {
            work.step(is_cancelled)?;
            let next = vertices.len();
            let target = *vertices.entry(edge.target.as_str()).or_insert(next);
            let next = vertices.len();
            let source = *vertices.entry(edge.source.as_str()).or_insert(next);
            if let Some(count) = fan_in.get_mut(target) {
                *count = count.saturating_add(1);
            }
            if let Some(count) = fan_out.get_mut(source) {
                *count = count.saturating_add(1);
            }
            pairs.push((target, source));
        }
        pairs.sort_unstable();
        pairs.dedup();
        let mut dependents_start = vec![0_usize; vertices.len() + 1];
        for &(target, _) in &pairs {
            dependents_start[target + 1] += 1;
        }
        for vertex in 0..vertices.len() {
            dependents_start[vertex + 1] += dependents_start[vertex];
        }
        let dependents = pairs.into_iter().map(|(_, source)| source).collect();
        Ok(Self {
            subject_vertices,
            fan_in,
            fan_out,
            dependents_start,
            dependents,
        })
    }

    fn vertex_count(&self) -> usize {
        self.dependents_start.len() - 1
    }

    fn dependents_of(&self, vertex: usize) -> &[usize] {
        &self.dependents[self.dependents_start[vertex]..self.dependents_start[vertex + 1]]
    }

    /// Count, for every subject, the distinct vertices that transitively
    /// depend on it (the subject itself excluded).
    ///
    /// Instead of one breadth-first search per subject, up to
    /// [`REVERSE_IMPACT_LANES`] subjects share one pass: each vertex carries a
    /// bit mask of the batch subjects it can reach through incoming edges, and
    /// a work list propagates a mask to the dependents until no mask grows. A vertex shared by many
    /// subjects of a batch is expanded once for all of them, so the work is
    /// proportional to the union of the batch's reverse closures rather than
    /// their sum. The counts equal the per-subject search exactly; batch
    /// order changes only the amount of work, and batches follow the subject
    /// locators so subjects of one file, which share most dependents, are
    /// usually batched together.
    fn reverse_impact_sizes(
        &self,
        subjects: &[&NodeRecord],
        work: &mut HotspotWork,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Vec<u64>, HotspotAnalysisError> {
        let mut order = (0..subjects.len()).collect::<Vec<_>>();
        order.sort_by(|left, right| {
            subjects[*left]
                .locator
                .cmp(&subjects[*right].locator)
                .then_with(|| subjects[*left].id.cmp(&subjects[*right].id))
        });
        let mut sizes = vec![0_u64; subjects.len()];
        let mut masks = vec![LaneMask::default(); self.vertex_count()];
        let mut queued = vec![false; self.vertex_count()];
        let mut touched = Vec::new();
        let mut queue = VecDeque::new();
        let mut reached = [0_u64; REVERSE_IMPACT_LANES];
        for batch in order.chunks(REVERSE_IMPACT_LANES) {
            for (lane, &position) in batch.iter().enumerate() {
                work.step(is_cancelled)?;
                let vertex = self.subject_vertices[position];
                if masks[vertex].is_empty() {
                    touched.push(vertex);
                }
                masks[vertex].set(lane);
                if !queued[vertex] {
                    queued[vertex] = true;
                    queue.push_back(vertex);
                }
            }
            while let Some(current) = queue.pop_front() {
                work.step(is_cancelled)?;
                queued[current] = false;
                let mask = masks[current];
                for &dependent in self.dependents_of(current) {
                    work.step(is_cancelled)?;
                    let grown = masks[dependent].union(mask);
                    if grown == masks[dependent] {
                        continue;
                    }
                    if masks[dependent].is_empty() {
                        touched.push(dependent);
                    }
                    masks[dependent] = grown;
                    if !queued[dependent] {
                        queued[dependent] = true;
                        queue.push_back(dependent);
                    }
                }
            }
            reached.fill(0);
            for vertex in touched.drain(..) {
                work.step(is_cancelled)?;
                std::mem::take(&mut masks[vertex]).for_each_lane(|lane| reached[lane] += 1);
            }
            for (lane, &position) in batch.iter().enumerate() {
                sizes[position] = reached[lane].saturating_sub(1);
            }
        }
        Ok(sizes)
    }
}

struct HotspotWork {
    used: usize,
    maximum: usize,
}

impl HotspotWork {
    const fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    fn step(
        &mut self,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<(), HotspotAnalysisError> {
        if is_cancelled() {
            return Err(HotspotAnalysisError::Cancelled);
        }
        if self.used >= self.maximum {
            return Err(HotspotAnalysisError::ResourceExhausted);
        }
        self.used = self.used.saturating_add(1);
        Ok(())
    }
}

/// Compute the canonical weighted hotspot total using integer basis points.
///
/// Agent projections use this helper as well so validation cannot drift from
/// the analyzer's rounding and saturation rules.
#[must_use]
pub fn hotspot_weighted_total(layers: [(u32, u32); 5]) -> u32 {
    layers
        .into_iter()
        .map(|(normalized, weight)| {
            u32::try_from(u64::from(normalized) * u64::from(weight) / u64::from(BASIS_POINTS_MAX))
                .unwrap_or(BASIS_POINTS_MAX)
        })
        .fold(0, u32::saturating_add)
        .min(BASIS_POINTS_MAX)
}

#[cfg(test)]
mod tests {
    use depgraph_store::{CoverageRecord, EdgeRecord, GraphSnapshot, NodeRecord, ScanRecord};
    use serde_json::json;

    use crate::health::Confidence;

    use super::*;

    fn node(id: &str) -> NodeRecord {
        let path = format!("{}.rs", id.strip_prefix("file:").unwrap_or(id));
        NodeRecord {
            id: id.to_owned(),
            kind: "file".to_owned(),
            locator: format!("repo://{id}"),
            display_name: id.to_owned(),
            properties: json!({"path": path}),
        }
    }

    fn edge(source: &str, target: &str) -> EdgeRecord {
        EdgeRecord {
            id: format!("{source}->{target}"),
            site_id: None,
            source: source.to_owned(),
            target: target.to_owned(),
            kind: "imports".to_owned(),
            phase: "source".to_owned(),
            environment: "host".to_owned(),
            profile_id: "p".to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({}),
            generated: false,
        }
    }

    fn snapshot(nodes: Vec<NodeRecord>, edges: Vec<EdgeRecord>) -> GraphSnapshot {
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan-hot".to_owned(),
                root: "/tmp".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "2026-01-01T00:00:00Z".to_owned(),
                completed_at: Some("2026-01-01T00:00:01Z".to_owned()),
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: Some("c".repeat(40)),
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
            analysis_dependency_coverage: None,
        }
    }

    #[test]
    fn issue_423_hotspot_reverse_impact_is_transitive_and_missing_layers_stay_zero() {
        let graph = snapshot(
            vec![
                node("file:b"),
                node("file:a"),
                node("file:c"),
                node("file:d"),
            ],
            vec![
                edge("file:a", "file:c"),
                edge("file:b", "file:c"),
                edge("file:d", "file:a"),
            ],
        );
        let findings = score_hotspots(
            &graph,
            DEFAULT_HOTSPOT_WEIGHTS,
            &BTreeMap::new(),
            &BTreeMap::new(),
            HotspotLayerAvailability {
                churn: false,
                runtime: false,
            },
        )
        .expect("valid hotspot weights");
        assert!(
            findings
                .iter()
                .all(|finding| finding.suppressions.is_empty())
        );
        assert!(findings.iter().all(|finding| {
            finding
                .blockers
                .iter()
                .any(|blocker| blocker.kind == BlockerKind::ChurnUnavailable)
        }));
        let first = findings.first().expect("ranked hotspot");
        assert_eq!(first.subject_id, "file:c");
        let scores = first
            .hotspot_scores
            .as_ref()
            .expect("structured hotspot scores");
        assert_eq!(scores.fan_in.raw, 2);
        assert_eq!(scores.reverse_impact.raw, 3);
        assert_eq!(
            scores.fan_in.weight_basis_points,
            DEFAULT_HOTSPOT_WEIGHTS.fan_in
        );
        assert_eq!(scores.total, 5_000);
        assert_eq!(first.confidence, Confidence::Probable);
    }

    #[test]
    fn issue_596_symbol_hotspot_location_carries_the_declaration_span() {
        let symbol = NodeRecord {
            id: "symbol:Helper".to_owned(),
            kind: "symbol".to_owned(),
            locator: "go-symbol:example.com/pkg.Helper".to_owned(),
            display_name: "Helper".to_owned(),
            properties: json!({
                "source_path": "svc/pkg/helper.go",
                "source_span": {"start_line": 7, "start_column": 6, "end_line": 7, "end_column": 12},
            }),
        };
        let churn = BTreeMap::from([("svc/pkg/helper.go".to_owned(), 4)]);
        let findings = score_hotspots(
            &snapshot(vec![symbol, node("file:a")], Vec::new()),
            DEFAULT_HOTSPOT_WEIGHTS,
            &churn,
            &BTreeMap::new(),
            HotspotLayerAvailability {
                churn: true,
                runtime: false,
            },
        )
        .expect("valid hotspot weights");
        let helper = findings
            .iter()
            .find(|finding| finding.subject_id == "symbol:Helper")
            .expect("symbol hotspot");
        assert_eq!(
            helper.location,
            Some(SourceLocation {
                path: "svc/pkg/helper.go".to_owned(),
                start_line: Some(7),
                start_column: Some(6),
                end_line: Some(7),
                end_column: Some(12),
            })
        );
        let scores = helper.hotspot_scores.as_ref().expect("hotspot scores");
        assert_eq!(scores.git_churn.raw, 4);
        // A file has no declaration span, so its location stays path-only.
        let file = findings
            .iter()
            .find(|finding| finding.subject_id == "file:a")
            .and_then(|finding| finding.location.as_ref())
            .expect("file location");
        assert_eq!((file.path.as_str(), file.start_line), ("a.rs", None));
    }

    #[test]
    fn issue_423_hotspot_ties_use_node_id_and_churn_maps_by_repository_path() {
        let graph = snapshot(vec![node("file:b"), node("file:a")], Vec::new());
        let tied = score_hotspots(
            &graph,
            DEFAULT_HOTSPOT_WEIGHTS,
            &BTreeMap::new(),
            &BTreeMap::new(),
            HotspotLayerAvailability {
                churn: false,
                runtime: false,
            },
        )
        .expect("valid hotspot weights");
        let ids = tied
            .iter()
            .map(|finding| finding.subject_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["file:a", "file:b"]);

        let churn = BTreeMap::from([("b.rs".to_owned(), 3)]);
        let ranked = score_hotspots(
            &graph,
            DEFAULT_HOTSPOT_WEIGHTS,
            &churn,
            &BTreeMap::new(),
            HotspotLayerAvailability {
                churn: true,
                runtime: false,
            },
        )
        .expect("valid hotspot weights");
        assert_eq!(ranked[0].subject_id, "file:b");
        let scores = ranked[0]
            .hotspot_scores
            .as_ref()
            .expect("structured hotspot scores");
        assert_eq!(scores.git_churn.raw, 3);
        assert_eq!(scores.git_churn.normalized_basis_points, 10_000);
        assert!(scores.git_churn.available);
        assert!(!scores.runtime.available);
    }

    #[test]
    fn issue_423_hotspot_weights_reject_out_of_range_and_cap_at_10000() {
        assert!(HotspotWeights::try_new(10_001, 0, 0, 0, 0).is_err());
        assert!(HotspotWeights::try_new(4_000, 4_000, 4_000, 0, 0).is_err());
        let maxed = rank_normalize_basis_points(&[0, 10_000]);
        assert_eq!(maxed, vec![0, 10_000]);
    }

    #[test]
    fn issue_440_direct_hotspot_weights_are_revalidated() {
        assert!(
            (HotspotWeights {
                fan_in: 10_001,
                fan_out: 0,
                reverse_impact: 0,
                git_churn: 0,
                runtime: 0,
            })
            .validate()
            .is_err()
        );
        assert!(
            (HotspotWeights {
                fan_in: 4_000,
                fan_out: 4_000,
                reverse_impact: 4_000,
                git_churn: 0,
                runtime: 0,
            })
            .validate()
            .is_err()
        );
        assert!(DEFAULT_HOTSPOT_WEIGHTS.validate().is_ok());
    }

    #[test]
    fn issue_440_hotspot_weight_changes_create_new_finding_identity() {
        let graph = snapshot(vec![node("file:a"), node("file:b")], Vec::new());
        let default_findings = score_hotspots(
            &graph,
            DEFAULT_HOTSPOT_WEIGHTS,
            &BTreeMap::new(),
            &BTreeMap::new(),
            HotspotLayerAvailability::default(),
        )
        .expect("valid default hotspot weights");
        let changed_weights = HotspotWeights::try_new(3_000, 1_000, 2_500, 2_000, 1_500)
            .expect("valid changed hotspot weights");
        let changed_findings = score_hotspots(
            &graph,
            changed_weights,
            &BTreeMap::new(),
            &BTreeMap::new(),
            HotspotLayerAvailability::default(),
        )
        .expect("valid changed hotspot weights");

        let default_finding = default_findings
            .iter()
            .find(|finding| finding.subject_id == "file:a")
            .expect("default finding");
        let changed_finding = changed_findings
            .iter()
            .find(|finding| finding.subject_id == "file:a")
            .expect("changed finding");
        assert_ne!(default_finding.id, changed_finding.id);
        assert_ne!(default_finding.fingerprint, changed_finding.fingerprint);
    }

    #[test]
    fn issue_440_cancellable_hotspot_analyzer_rejects_invalid_weights() {
        let graph = snapshot(vec![node("file:a")], Vec::new());
        assert_eq!(
            score_hotspots_cancellable(
                &graph,
                HotspotWeights {
                    fan_in: 10_001,
                    fan_out: 0,
                    reverse_impact: 0,
                    git_churn: 0,
                    runtime: 0,
                },
                &BTreeMap::new(),
                &BTreeMap::new(),
                HotspotLayerAvailability::default(),
                usize::MAX,
                usize::MAX,
                || false,
            ),
            Err(HotspotAnalysisError::InvalidInput)
        );
        assert_eq!(
            score_hotspots_cancellable(
                &graph,
                HotspotWeights {
                    fan_in: 4_000,
                    fan_out: 4_000,
                    reverse_impact: 4_000,
                    git_churn: 0,
                    runtime: 0,
                },
                &BTreeMap::new(),
                &BTreeMap::new(),
                HotspotLayerAvailability::default(),
                usize::MAX,
                usize::MAX,
                || false,
            ),
            Err(HotspotAnalysisError::InvalidInput)
        );
    }

    #[test]
    fn issue_440_non_cancellable_hotspot_analyzer_rejects_invalid_weights() {
        let graph = snapshot(vec![node("file:a")], Vec::new());
        assert_eq!(
            score_hotspots(
                &graph,
                HotspotWeights {
                    fan_in: 10_001,
                    fan_out: 0,
                    reverse_impact: 0,
                    git_churn: 0,
                    runtime: 0,
                },
                &BTreeMap::new(),
                &BTreeMap::new(),
                HotspotLayerAvailability::default(),
            ),
            Err(HotspotAnalysisError::InvalidInput)
        );
    }

    #[test]
    fn issue_423_hotspot_subject_discovery_is_bounded_and_cancellable() {
        let graph = snapshot(vec![node("file:a")], Vec::new());
        assert_eq!(
            score_hotspots_cancellable(
                &graph,
                DEFAULT_HOTSPOT_WEIGHTS,
                &BTreeMap::new(),
                &BTreeMap::new(),
                HotspotLayerAvailability::default(),
                0,
                usize::MAX,
                || false,
            ),
            Err(HotspotAnalysisError::SubjectLimit)
        );
        assert_eq!(
            score_hotspots_cancellable(
                &graph,
                DEFAULT_HOTSPOT_WEIGHTS,
                &BTreeMap::new(),
                &BTreeMap::new(),
                HotspotLayerAvailability::default(),
                usize::MAX,
                0,
                || false,
            ),
            Err(HotspotAnalysisError::ResourceExhausted)
        );
        assert_eq!(
            score_hotspots_cancellable(
                &graph,
                DEFAULT_HOTSPOT_WEIGHTS,
                &BTreeMap::new(),
                &BTreeMap::new(),
                HotspotLayerAvailability::default(),
                usize::MAX,
                usize::MAX,
                || true,
            ),
            Err(HotspotAnalysisError::Cancelled)
        );
    }

    fn issue_562_node(id: &str, kind: &str, locator: &str, path: Option<&str>) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: locator.to_owned(),
            display_name: id.to_owned(),
            properties: path.map_or_else(|| json!({}), |path| json!({ "path": path })),
        }
    }

    fn issue_562_edge(ordinal: usize, source: &str, target: &str, kind: &str) -> EdgeRecord {
        let mut record = edge(source, target);
        record.id = format!("edge:{ordinal:08}");
        record.kind = kind.to_owned();
        record
    }

    /// The per-subject breadth-first search that scored reverse impact before
    /// #562, kept as the reference. Returns the sizes and the work it counted.
    fn issue_562_reference_reverse_impact(
        snapshot: &GraphSnapshot,
        subjects: &[&NodeRecord],
    ) -> (Vec<u64>, usize) {
        let mut work = snapshot.edges.len();
        let mut incoming = BTreeMap::<&str, Vec<&str>>::new();
        for edge in &snapshot.edges {
            incoming
                .entry(edge.target.as_str())
                .or_default()
                .push(edge.source.as_str());
        }
        let mut sizes = Vec::with_capacity(subjects.len());
        for subject in subjects {
            work += 1;
            let mut seen = std::collections::BTreeSet::from([subject.id.as_str()]);
            let mut queue = VecDeque::from([subject.id.as_str()]);
            while let Some(current) = queue.pop_front() {
                work += 1;
                for dependent in incoming.get(current).into_iter().flatten() {
                    work += 1;
                    if seen.insert(dependent) {
                        queue.push_back(dependent);
                    }
                }
            }
            sizes.push(u64::try_from(seen.len() - 1).expect("size fits"));
        }
        (sizes, work)
    }

    fn issue_562_subjects(snapshot: &GraphSnapshot) -> Vec<&NodeRecord> {
        snapshot
            .nodes
            .iter()
            .filter(|node| is_hotspot_subject_kind(&node.kind))
            .collect()
    }

    fn issue_562_lane_reverse_impact(snapshot: &GraphSnapshot) -> Vec<u64> {
        let subjects = issue_562_subjects(snapshot);
        let mut work = HotspotWork::new(usize::MAX);
        let graph = HotspotGraph::build(snapshot, &subjects, &mut work, &mut || false)
            .expect("unbounded graph build");
        graph
            .reverse_impact_sizes(&subjects, &mut work, &mut || false)
            .expect("unbounded reverse impact")
    }

    /// A deterministic graph with cycles, self-loops, duplicate edges,
    /// non-subject vertices, and endpoints that have no node record.
    fn issue_562_irregular_snapshot(seed: u64, subjects: usize, edges: usize) -> GraphSnapshot {
        let mut state = seed;
        let mut next = move |bound: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).expect("31-bit value") % bound
        };
        let externals = subjects / 4 + 1;
        let mut nodes = Vec::new();
        for index in 0..subjects {
            let kind = HOTSPOT_SUBJECT_KINDS[index % HOTSPOT_SUBJECT_KINDS.len()];
            let path = format!("src/f{:03}.rs", index % 17);
            nodes.push(issue_562_node(
                &format!("n:{index:05}"),
                kind,
                &format!("repo://{path}#{index}"),
                Some(&path),
            ));
        }
        for index in 0..externals {
            nodes.push(issue_562_node(
                &format!("x:{index:05}"),
                "unknown_target",
                &format!("external://{index}"),
                None,
            ));
        }
        let vertex = |choice: usize| match choice % 10 {
            0 => format!("x:{:05}", choice % externals),
            1 => format!("dangling:{}", choice % 7),
            _ => format!("n:{:05}", choice % subjects),
        };
        let mut records = Vec::new();
        for ordinal in 0..edges {
            let source = vertex(next(subjects * 10));
            let target = if next(20) == 0 {
                source.clone()
            } else {
                vertex(next(subjects * 10))
            };
            records.push(issue_562_edge(ordinal, &source, &target, "imports"));
            if next(5) == 0 {
                records.push(issue_562_edge(edges + ordinal, &source, &target, "calls"));
            }
        }
        snapshot(nodes, records)
    }

    #[test]
    fn issue_562_batched_reverse_impact_equals_per_subject_search() {
        for (seed, subjects, edges) in [
            (1, 1, 0),
            (2, 63, 40),
            (3, 64, 200),
            (4, 65, 300),
            (5, 200, 150),
            (6, 200, 900),
            (7, 333, 2_500),
            (8, 255, 1_200),
            (9, 256, 1_500),
            (10, 257, 1_800),
            (11, 900, 6_000),
        ] {
            let graph = issue_562_irregular_snapshot(seed, subjects, edges);
            let reference_subjects = issue_562_subjects(&graph);
            let (expected, _) = issue_562_reference_reverse_impact(&graph, &reference_subjects);
            assert_eq!(
                issue_562_lane_reverse_impact(&graph),
                expected,
                "seed {seed}: batched reverse impact diverged from the per-subject search"
            );
        }
    }

    /// Shape of the depgraph-cli snapshot in #562 at a smaller scale: files
    /// import earlier files (with a few cycles), declare symbols that call
    /// each other, and reference external targets. Imports repeat one
    /// source/target pair, as `type_uses` and `expands` do in real scans.
    fn issue_562_large_snapshot() -> GraphSnapshot {
        const FILES: usize = 120;
        const SYMBOLS_PER_FILE: usize = 75;
        const EXTERNALS: usize = 500;
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut push = |source: String, target: String, kind: &str| {
            let ordinal = edges.len();
            edges.push(issue_562_edge(ordinal, &source, &target, kind));
        };
        for file in 0..FILES {
            let path = format!("crates/core/src/f{file:03}.rs");
            nodes.push(issue_562_node(
                &format!("file:{file:03}"),
                "file",
                &format!("file:{path}"),
                Some(&path),
            ));
            for symbol in 0..SYMBOLS_PER_FILE {
                nodes.push(issue_562_node(
                    &format!("symbol:{file:03}:{symbol:02}"),
                    "symbol",
                    &format!("symbol:{path}#s{symbol:02}"),
                    Some(&path),
                ));
            }
        }
        for external in 0..EXTERNALS {
            nodes.push(issue_562_node(
                &format!("unknown:{external:03}"),
                "unknown_target",
                &format!("unknown:{external:03}"),
                None,
            ));
        }
        for file in 0..FILES {
            for back in 1..=3 {
                if let Some(imported) = file.checked_sub(back) {
                    for _ in 0..3 {
                        push(
                            format!("file:{file:03}"),
                            format!("file:{imported:03}"),
                            "imports",
                        );
                    }
                }
            }
            if file % 10 == 9 {
                push(
                    format!("file:{:03}", file - 9),
                    format!("file:{file:03}"),
                    "imports",
                );
            }
            for symbol in 0..SYMBOLS_PER_FILE {
                push(
                    format!("file:{file:03}"),
                    format!("symbol:{file:03}:{symbol:02}"),
                    "declares",
                );
                if symbol > 0 {
                    push(
                        format!("symbol:{file:03}:{symbol:02}"),
                        format!("symbol:{file:03}:{:02}", symbol - 1),
                        "calls",
                    );
                }
                push(
                    format!("symbol:{file:03}:{symbol:02}"),
                    format!(
                        "unknown:{:03}",
                        (file * SYMBOLS_PER_FILE + symbol) % EXTERNALS
                    ),
                    "type_uses",
                );
            }
        }
        snapshot(nodes, edges)
    }

    fn issue_562_findings_digest(findings: &[HealthFinding]) -> String {
        use sha2::{Digest as _, Sha256};
        let canonical = serde_json::to_string(findings).expect("findings serialize");
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }

    #[test]
    fn issue_562_large_snapshot_hotspots_fit_the_service_budget_with_unchanged_scores() {
        let graph = issue_562_large_snapshot();
        let subjects = issue_562_subjects(&graph);
        let maximum_work = crate::service_limits::MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS;
        let (expected_reverse, reference_work) =
            issue_562_reference_reverse_impact(&graph, &subjects);
        assert!(
            reference_work > maximum_work,
            "fixture must exhaust the service budget under the per-subject search \
             (needed {reference_work} work items)"
        );

        let findings = score_hotspots_cancellable(
            &graph,
            DEFAULT_HOTSPOT_WEIGHTS,
            &BTreeMap::new(),
            &BTreeMap::new(),
            HotspotLayerAvailability::default(),
            crate::service_limits::MAX_HEALTH_FINDINGS,
            maximum_work,
            || false,
        )
        .expect("hotspot scoring fits the default service budget");
        assert_eq!(findings.len(), subjects.len());
        let reverse_by_subject = subjects
            .iter()
            .zip(&expected_reverse)
            .map(|(node, size)| (node.id.as_str(), *size))
            .collect::<BTreeMap<_, _>>();
        for finding in &findings {
            let scores = finding.hotspot_scores.as_ref().expect("hotspot scores");
            assert_eq!(
                scores.reverse_impact.raw,
                reverse_by_subject[finding.subject_id.as_str()],
                "reverse impact of {} changed",
                finding.subject_id
            );
        }
        // Digest of the complete ranking (order, IDs, fingerprints, raw and
        // normalized layers) that the per-subject search produced before #562.
        assert_eq!(
            issue_562_findings_digest(&findings),
            "c05d18749daff4f75b6493c4b53008855271d6aebbbf98c691b1c2ff3f3c267f",
            "hotspot ranking differs from the pre-#562 analyzer"
        );
    }

    /// Shape of the Rust HIR snapshot in #590 at a smaller scale: besides
    /// files and functions, HIR records parameters, local variables, and
    /// closures as `symbol` subjects, plus many non-subject nodes. Functions
    /// declare their bindings, locals use parameters and external types,
    /// closures capture locals, functions call each other within and across
    /// files, and files import earlier files.
    fn issue_590_hir_scale_snapshot() -> GraphSnapshot {
        const FILES: usize = 60;
        const FUNCTIONS_PER_FILE: usize = 40;
        const PARAMETERS: usize = 3;
        const LOCALS: usize = 5;
        const EXPRESSIONS: usize = 3;
        const EXTERNALS: usize = 700;
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut push = |source: &str, target: &str, kind: &str| {
            let ordinal = edges.len();
            edges.push(issue_562_edge(ordinal, source, target, kind));
        };
        let symbol = |id: &str, symbol_kind: &str, locator: &str, path: &str| NodeRecord {
            id: id.to_owned(),
            kind: "symbol".to_owned(),
            locator: locator.to_owned(),
            display_name: id.to_owned(),
            properties: json!({ "path": path, "symbol_kind": symbol_kind }),
        };
        for external in 0..EXTERNALS {
            nodes.push(issue_562_node(
                &format!("unknown:{external:03}"),
                "unknown_target",
                &format!("unknown:{external:03}"),
                None,
            ));
        }
        for module in 0..FILES / 10 {
            let path = format!("crates/core/src/m{module}/mod.rs");
            nodes.push(issue_562_node(
                &format!("module:{module}"),
                "module",
                &format!("module:{path}"),
                Some(&path),
            ));
        }
        for file in 0..FILES {
            let path = format!("crates/core/src/m{}/f{file:03}.rs", file / 10);
            let file_id = format!("file:{file:03}");
            nodes.push(issue_562_node(
                &file_id,
                "file",
                &format!("file:{path}"),
                Some(&path),
            ));
            push(&format!("module:{}", file / 10), &file_id, "declares");
            for back in 1..=2 {
                if let Some(imported) = file.checked_sub(back) {
                    for _ in 0..2 {
                        push(&file_id, &format!("file:{imported:03}"), "imports");
                    }
                }
            }
            if file % 10 == 9 {
                push(&format!("file:{:03}", file - 9), &file_id, "imports");
            }
            for function in 0..FUNCTIONS_PER_FILE {
                let function_id = format!("fn:{file:03}:{function:02}");
                let locator = format!("symbol:{path}#fn{function:02}");
                nodes.push(symbol(&function_id, "function", &locator, &path));
                push(&file_id, &function_id, "declares");
                if function > 0 {
                    push(
                        &function_id,
                        &format!("fn:{file:03}:{:02}", function - 1),
                        "calls",
                    );
                }
                if function % 8 == 0
                    && let Some(callee) = file.checked_sub(1)
                {
                    push(
                        &function_id,
                        &format!("fn:{callee:03}:{function:02}"),
                        "calls",
                    );
                }
                for parameter in 0..PARAMETERS {
                    let id = format!("{function_id}:param{parameter}");
                    nodes.push(symbol(
                        &id,
                        "parameter",
                        &format!("{locator}/param{parameter}"),
                        &path,
                    ));
                    push(&function_id, &id, "declares");
                }
                for local in 0..LOCALS {
                    let id = format!("{function_id}:local{local}");
                    nodes.push(symbol(
                        &id,
                        "local_variable",
                        &format!("{locator}/local{local}"),
                        &path,
                    ));
                    push(&function_id, &id, "declares");
                    push(
                        &id,
                        &format!("{function_id}:param{}", local % PARAMETERS),
                        "uses",
                    );
                    push(
                        &id,
                        &format!(
                            "unknown:{:03}",
                            ((file * FUNCTIONS_PER_FILE + function) * LOCALS + local) % EXTERNALS
                        ),
                        "type_uses",
                    );
                    for expression in 0..EXPRESSIONS {
                        let expression_id = format!("{id}:expr{expression}");
                        nodes.push(issue_562_node(
                            &expression_id,
                            "expression",
                            &format!("{locator}/local{local}/expr{expression}"),
                            Some(&path),
                        ));
                        push(&id, &expression_id, "contains");
                    }
                }
                let closure = format!("{function_id}:closure");
                nodes.push(symbol(
                    &closure,
                    "closure",
                    &format!("{locator}/closure"),
                    &path,
                ));
                push(&function_id, &closure, "declares");
                push(&function_id, &closure, "calls");
                for local in 0..2 {
                    push(&closure, &format!("{function_id}:local{local}"), "captures");
                }
            }
        }
        snapshot(nodes, edges)
    }

    #[test]
    fn issue_590_hir_scale_snapshot_fits_the_hotspot_budget_with_unchanged_scores() {
        use crate::service_limits::{
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS, MAX_HEALTH_FINDINGS,
            MAX_HOTSPOT_PREPROCESSING_WORK_ITEMS, MAX_HOTSPOT_SUBJECTS,
        };
        let graph = issue_590_hir_scale_snapshot();
        let subjects = issue_562_subjects(&graph);
        assert!(
            subjects.len() > MAX_HEALTH_FINDINGS,
            "fixture must exceed the health finding limit that hotspots used to borrow \
             ({} subjects)",
            subjects.len()
        );
        assert_eq!(
            score_hotspots_cancellable(
                &graph,
                DEFAULT_HOTSPOT_WEIGHTS,
                &BTreeMap::new(),
                &BTreeMap::new(),
                HotspotLayerAvailability::default(),
                usize::MAX,
                MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
                || false,
            ),
            Err(HotspotAnalysisError::ResourceExhausted),
            "fixture must exhaust the graph-service budget that hotspots used to borrow"
        );

        let findings = score_hotspots_cancellable(
            &graph,
            DEFAULT_HOTSPOT_WEIGHTS,
            &BTreeMap::new(),
            &BTreeMap::new(),
            HotspotLayerAvailability::default(),
            MAX_HOTSPOT_SUBJECTS,
            MAX_HOTSPOT_PREPROCESSING_WORK_ITEMS,
            || false,
        )
        .expect("hotspot scoring fits the default hotspot limits");
        assert_eq!(findings.len(), subjects.len());
        // Digest of the complete ranking (order, IDs, fingerprints, raw and
        // normalized layers) that the 64-lane analyzer produced before #590.
        assert_eq!(
            issue_562_findings_digest(&findings),
            "63fbcad18b400d58a86afb9f0d312502c04bf7cb9d2019fcf2f1899e2dccf1fa",
            "hotspot ranking differs from the pre-#590 analyzer"
        );
    }
}
