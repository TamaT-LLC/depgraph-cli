use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
        if [fan_in, fan_out, reverse_impact, git_churn, runtime]
            .into_iter()
            .any(|weight| weight > BASIS_POINTS_MAX)
        {
            return Err("hotspot weight exceeds 10000");
        }
        if weights.sum() > BASIS_POINTS_MAX {
            return Err("hotspot weights sum exceeds 10000");
        }
        Ok(weights)
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

#[derive(Clone, Debug, Default)]
pub struct HotspotLayerAvailability {
    pub churn: bool,
    pub runtime: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HotspotAnalysisError {
    #[error("hotspot analysis was cancelled")]
    Cancelled,
    #[error("hotspot analysis exhausted its bounded work budget")]
    ResourceExhausted,
}

#[must_use]
pub fn score_hotspots(
    snapshot: &GraphSnapshot,
    weights: HotspotWeights,
    churn: &BTreeMap<String, u64>,
    runtime: &BTreeMap<String, u64>,
    availability: HotspotLayerAvailability,
) -> Vec<HealthFinding> {
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
    .expect("unbounded, non-cancellable hotspot analysis cannot fail")
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
    let mut work = HotspotWork::new(maximum_work);
    let mut subjects = Vec::new();
    for node in &snapshot.nodes {
        work.step(&mut is_cancelled)?;
        if matches!(
            node.kind.as_str(),
            "file" | "module" | "symbol" | "type" | "route"
        ) {
            if subjects.len() >= maximum_subjects {
                return Err(HotspotAnalysisError::ResourceExhausted);
            }
            subjects.push(node);
        }
    }
    let mut subject_ids = BTreeSet::new();
    for node in &subjects {
        work.step(&mut is_cancelled)?;
        subject_ids.insert(node.id.as_str());
    }
    let mut fan_in_by_id = BTreeMap::<&str, u64>::new();
    let mut fan_out_by_id = BTreeMap::<&str, u64>::new();
    for edge in &snapshot.edges {
        work.step(&mut is_cancelled)?;
        if subject_ids.contains(edge.target.as_str()) {
            let count = fan_in_by_id.entry(edge.target.as_str()).or_insert(0);
            *count = count.saturating_add(1);
        }
        if subject_ids.contains(edge.source.as_str()) {
            let count = fan_out_by_id.entry(edge.source.as_str()).or_insert(0);
            *count = count.saturating_add(1);
        }
    }
    let reverse = reverse_impact_sizes(snapshot, &subjects, &mut work, &mut is_cancelled)?;
    let mut fan_in = Vec::with_capacity(subjects.len());
    let mut fan_out = Vec::with_capacity(subjects.len());
    let mut churn_values = Vec::with_capacity(subjects.len());
    let mut runtime_values = Vec::with_capacity(subjects.len());
    for node in &subjects {
        work.step(&mut is_cancelled)?;
        fan_in.push(fan_in_by_id.get(node.id.as_str()).copied().unwrap_or(0));
        fan_out.push(fan_out_by_id.get(node.id.as_str()).copied().unwrap_or(0));
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
                total: weighted_total([
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
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
        });
        findings.push(finish_finding(
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
                availability.churn && availability.runtime,
            ));
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

fn reverse_impact_sizes(
    snapshot: &GraphSnapshot,
    subjects: &[&NodeRecord],
    work: &mut HotspotWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<u64>, HotspotAnalysisError> {
    let mut incoming = BTreeMap::<&str, Vec<&str>>::new();
    for edge in &snapshot.edges {
        work.step(is_cancelled)?;
        incoming
            .entry(edge.target.as_str())
            .or_default()
            .push(edge.source.as_str());
    }
    let mut sizes = Vec::with_capacity(subjects.len());
    for subject in subjects {
        work.step(is_cancelled)?;
        let mut seen = BTreeSet::from([subject.id.as_str()]);
        let mut queue = VecDeque::from([subject.id.as_str()]);
        while let Some(current) = queue.pop_front() {
            work.step(is_cancelled)?;
            for dependent in incoming.get(current).into_iter().flatten() {
                work.step(is_cancelled)?;
                if seen.insert(dependent) {
                    queue.push_back(dependent);
                }
            }
        }
        sizes.push(u64::try_from(seen.len().saturating_sub(1)).unwrap_or(u64::MAX));
    }
    Ok(sizes)
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

fn weighted_total(layers: [(u32, u32); 5]) -> u32 {
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
        );
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
        assert!(first.reason.contains("raw fan-in=2"));
        assert!(first.reason.contains("reverse-impact=3"));
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
        );
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
        );
        assert_eq!(ranked[0].subject_id, "file:b");
        assert!(
            ranked[0]
                .reason
                .contains("raw fan-in=0 fan-out=0 reverse-impact=0 git-churn=3")
        );
    }

    #[test]
    fn issue_423_hotspot_weights_reject_out_of_range_and_cap_at_10000() {
        assert!(HotspotWeights::try_new(10_001, 0, 0, 0, 0).is_err());
        assert!(HotspotWeights::try_new(4_000, 4_000, 4_000, 0, 0).is_err());
        let maxed = rank_normalize_basis_points(&[0, 10_000]);
        assert_eq!(maxed, vec![0, 10_000]);
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
}
