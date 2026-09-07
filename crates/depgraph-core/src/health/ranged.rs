//! Range-scheduled unused analysis over the Store's bounded read API.
//!
//! The whole-snapshot path materializes every node, edge, site, and evidence
//! record before the first subject is analyzed, so its work is bounded only by
//! one budget covering the whole graph. This scheduler instead:
//!
//! 1. asks the Store for a [`HealthRangePlan`] computed from SQL aggregates
//!    (no graph row is materialized),
//! 2. loads the snapshot-wide context once under its own budget and builds
//!    the shared [`GlobalIndex`],
//! 3. loads and analyzes each range under its own budget, keyed by target so
//!    a subject sees every inbound edge and site regardless of which range the
//!    sources live in, re-splitting a range that overruns its estimate,
//! 4. checkpoints each completed range so an interrupted request resumes from
//!    the ranges that finished,
//! 5. merges the per-range findings into the same sorted collection the
//!    whole-snapshot path produces.
//!
//! A collection is only published when every range completed; the opt-in
//! partial view returns completed ranges with an `IncompleteCoverage` blocker
//! on every finding so nothing can be read as `Confirmed`.

use std::collections::{BTreeMap, HashSet, VecDeque};

use depgraph_store::{
    CoverageRecord, GraphSnapshot, HealthInputIdentity, HealthLayer, HealthRange,
    HealthRangeLimits, HealthRangePlan, HealthWorkBudget, HealthWorkError, ScanRecord, Store,
    health_range_subject_ids, health_work_error, resplit_health_range,
};
use serde::{Deserialize, Serialize};

use super::{
    BlockerKind, Confidence, FindingBlocker, HealthAnalysisError, HealthFinding, ManifestIdentity,
    budget::HealthAnalysisBudget,
    dependency::analyze_dependencies_with_budget,
    finding_fingerprint,
    range_checkpoint::{
        HealthRangeCheckpointKey, HealthRangeCheckpointPayload, HealthRangeCheckpointStore,
    },
    unused::{GlobalIndex, GlobalSource, LocalIndex, analyze_subjects},
};

/// Processing order of the planned ranges.
///
/// Findings never depend on the order; the option exists so callers (and the
/// determinism tests) can prove that.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeOrder {
    Forward,
    Reverse,
    /// Deterministic Fisher–Yates shuffle with the given seed.
    Seeded(u64),
}

/// Progress of the range phase, reported after every range.
#[derive(Clone, Copy, Debug)]
pub struct HealthRangeProgress<'a> {
    pub range: &'a HealthRange,
    pub completed: u32,
    pub planned: u32,
    pub reused: bool,
}

pub struct RangedUnusedOptions<'o> {
    pub limits: HealthRangeLimits,
    pub maximum_findings: usize,
    pub allow_partial: bool,
    pub order: RangeOrder,
    pub checkpoints: Option<HealthRangeCheckpointStore>,
    pub progress: Option<&'o mut dyn FnMut(HealthRangeProgress<'_>)>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRangeCounts {
    /// Ranges in the final plan, including re-split halves.
    pub total: u32,
    /// Ranges whose findings are available (computed now or reused).
    pub completed: u32,
    /// Ranges whose findings came from a valid checkpoint.
    pub reused: u32,
    /// Ranges that overran their budget and were split in half.
    pub resplit: u32,
    /// Ranges that could not complete even after the maximum re-split depth.
    pub failed: u32,
    /// Ranges left unanalysed because the request was cancelled or stopped
    /// after a failure.
    pub interrupted: u32,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthWorkReport {
    /// Rows the planner read (aggregates and sorted index scans only).
    pub planner: u64,
    /// Steps of the snapshot-wide context (load + index build).
    pub global_context: u64,
    /// Sum of the per-range steps (load + index + analysis) of computed ranges.
    pub ranges_total: u64,
    /// Largest single-range step count; must stay within `range_limit`.
    pub ranges_max: u64,
    /// The unchanged per-phase/per-range budget.
    pub range_limit: u64,
    /// Steps spent loading the dependency projection.
    pub dependencies_load: u64,
    /// Steps spent in dependency matching.
    pub dependencies: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckpointReport {
    pub enabled: bool,
    pub written: u32,
    pub reused: u32,
    pub write_failures: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthExecutionMode {
    /// Planned ranges over one scan's tables.
    Ranged,
    /// Whole-snapshot path (layered inputs: build deltas, runtime sessions,
    /// semantic no-op overlays).
    WholeSnapshot,
}

/// Execution diagnostics of one snapshot-scoped health request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRangeDiagnostics {
    pub mode: HealthExecutionMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<String>,
    pub layers: Vec<HealthLayer>,
    pub ranges: HealthRangeCounts,
    pub work: HealthWorkReport,
    pub checkpoints: HealthCheckpointReport,
    /// `true` only for the opt-in partial view of an incomplete range set.
    pub partial: bool,
    /// Peak resident set size of this process (Linux `VmHWM`), when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_rss_kib: Option<u64>,
}

impl HealthRangeDiagnostics {
    #[must_use]
    pub fn whole_snapshot(layers: Vec<HealthLayer>, range_limit: u64) -> Self {
        Self {
            mode: HealthExecutionMode::WholeSnapshot,
            plan_digest: None,
            layers,
            ranges: HealthRangeCounts::default(),
            work: HealthWorkReport {
                range_limit,
                ..HealthWorkReport::default()
            },
            checkpoints: HealthCheckpointReport::default(),
            partial: false,
            peak_rss_kib: peak_rss_kib(),
        }
    }

    /// Stable summary of the range status, bound into the collection digest of
    /// a partial view so it never shares a digest with a complete collection.
    #[must_use]
    pub fn partial_range_status(&self) -> Option<String> {
        self.partial.then(|| {
            format!(
                "ranges:{}/{} failed:{} interrupted:{}",
                self.ranges.completed,
                self.ranges.total,
                self.ranges.failed,
                self.ranges.interrupted
            )
        })
    }
}

pub struct RangedUnusedOutcome {
    pub findings: Vec<HealthFinding>,
    pub diagnostics: HealthRangeDiagnostics,
    pub scan: ScanRecord,
    pub coverage: CoverageRecord,
}

/// A bounded-work failure together with what did complete.
#[derive(Debug)]
pub struct RangedHealthFailure {
    pub error: HealthAnalysisError,
    pub diagnostics: HealthRangeDiagnostics,
}

#[derive(Debug, thiserror::Error)]
pub enum RangedHealthError {
    #[error("{}", .0.error)]
    Analysis(Box<RangedHealthFailure>),
    #[error(transparent)]
    Store(anyhow::Error),
}

impl RangedHealthError {
    #[must_use]
    pub fn diagnostics(&self) -> Option<&HealthRangeDiagnostics> {
        match self {
            Self::Analysis(failure) => Some(&failure.diagnostics),
            Self::Store(_) => None,
        }
    }
}

/// Bridge between the core budget/cancellation pair and the store's trait.
struct RangeBudget<'c, F: FnMut() -> bool> {
    inner: HealthAnalysisBudget,
    is_cancelled: &'c mut F,
}

impl<F: FnMut() -> bool> HealthWorkBudget for RangeBudget<'_, F> {
    fn step(&mut self) -> Result<(), HealthWorkError> {
        self.inner
            .step(self.is_cancelled)
            .map_err(|error| match error {
                HealthAnalysisError::Cancelled => HealthWorkError::Cancelled,
                HealthAnalysisError::ResourceExhausted | HealthAnalysisError::Integrity => {
                    HealthWorkError::ResourceExhausted
                }
            })
    }
}

fn analysis_error(error: &anyhow::Error) -> Option<HealthAnalysisError> {
    health_work_error(error).map(|error| match error {
        HealthWorkError::Cancelled => HealthAnalysisError::Cancelled,
        HealthWorkError::ResourceExhausted => HealthAnalysisError::ResourceExhausted,
    })
}

/// Peak resident set size in KiB from `/proc/self/status` (Linux only).
#[must_use]
pub fn peak_rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status.lines().find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .ok()
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn order_ranges(mut ranges: Vec<HealthRange>, order: RangeOrder) -> Vec<HealthRange> {
    match order {
        RangeOrder::Forward => {}
        RangeOrder::Reverse => ranges.reverse(),
        RangeOrder::Seeded(seed) => {
            // xorshift64* keeps the permutation deterministic without a
            // random-number dependency.
            let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut next = move || {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                state.wrapping_mul(0x2545_F491_4F6C_DD1D)
            };
            for index in (1..ranges.len()).rev() {
                let swap = (next() % (index as u64 + 1)) as usize;
                ranges.swap(index, swap);
            }
        }
    }
    ranges
}

struct RangeRun {
    findings: Vec<HealthFinding>,
    subjects_analyzed: u64,
    work_used: u64,
}

enum RangeStep {
    Completed(RangeRun),
    Overrun,
    Cancelled,
    Integrity,
}

fn run_range(
    store: &Store,
    plan: &HealthRangePlan,
    range: &HealthRange,
    global: &GlobalIndex<'_>,
    limits: &HealthRangeLimits,
    maximum_findings: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<RangeStep, anyhow::Error> {
    let mut budget = RangeBudget {
        inner: HealthAnalysisBudget::new(
            usize::try_from(limits.per_range_work).unwrap_or(usize::MAX),
        ),
        is_cancelled,
    };
    let input = match store.load_health_range(plan, range, &mut budget) {
        Ok(input) => input,
        Err(error) => {
            return match analysis_error(&error) {
                Some(HealthAnalysisError::Cancelled) => Ok(RangeStep::Cancelled),
                Some(_) => Ok(RangeStep::Overrun),
                None => Err(error),
            };
        }
    };
    let RangeBudget {
        mut inner,
        is_cancelled,
    } = budget;
    let dynamic_site_ids = input
        .dynamic_site_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let analysed = LocalIndex::build(
        global,
        &input.subjects,
        &input.inbound_edges,
        &input.inbound_sites,
        dynamic_site_ids,
        &mut inner,
        is_cancelled,
    )
    .and_then(|local| {
        analyze_subjects(
            global,
            &local,
            &input.subjects,
            maximum_findings,
            &mut inner,
            is_cancelled,
        )
    });
    Ok(match analysed {
        Ok(findings) => RangeStep::Completed(RangeRun {
            findings,
            subjects_analyzed: input.subjects.len() as u64,
            work_used: inner.used() as u64,
        }),
        Err(HealthAnalysisError::Cancelled) => RangeStep::Cancelled,
        Err(HealthAnalysisError::ResourceExhausted) => RangeStep::Overrun,
        Err(HealthAnalysisError::Integrity) => RangeStep::Integrity,
    })
}

/// Plan, load, and analyze the unused findings of `identity` in bounded ranges.
///
/// `identity` must be plain (a single `Scan` layer); layered inputs take the
/// whole-snapshot path in `service_health`.
pub fn analyze_unused_ranged(
    store: &Store,
    identity: &HealthInputIdentity,
    options: RangedUnusedOptions<'_>,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<RangedUnusedOutcome, RangedHealthError> {
    let RangedUnusedOptions {
        limits,
        maximum_findings,
        allow_partial,
        order,
        checkpoints,
        mut progress,
    } = options;
    let mut diagnostics = HealthRangeDiagnostics {
        mode: HealthExecutionMode::Ranged,
        plan_digest: None,
        layers: identity.layers.clone(),
        ranges: HealthRangeCounts::default(),
        work: HealthWorkReport {
            range_limit: limits.per_range_work,
            ..HealthWorkReport::default()
        },
        checkpoints: HealthCheckpointReport {
            enabled: checkpoints.is_some(),
            ..HealthCheckpointReport::default()
        },
        partial: false,
        peak_rss_kib: None,
    };
    let fail = |error: HealthAnalysisError, mut diagnostics: HealthRangeDiagnostics| {
        diagnostics.peak_rss_kib = peak_rss_kib();
        RangedHealthError::Analysis(Box::new(RangedHealthFailure { error, diagnostics }))
    };

    // Phase 0: plan from aggregates only.
    let plan = match store.health_range_plan(identity, &limits, &mut || is_cancelled()) {
        Ok(plan) => plan,
        Err(error) => {
            return Err(match analysis_error(&error) {
                Some(error) => fail(error, diagnostics),
                None => RangedHealthError::Store(error),
            });
        }
    };
    diagnostics.plan_digest = Some(plan.plan_digest.clone());
    diagnostics.work.planner = plan.planner_work_used;
    diagnostics.ranges.total = plan.ranges.len() as u32;

    // Phase 1: snapshot-wide context under its own budget.
    let per_range_work = usize::try_from(limits.per_range_work).unwrap_or(usize::MAX);
    let mut global_budget = RangeBudget {
        inner: HealthAnalysisBudget::new(per_range_work),
        is_cancelled: &mut is_cancelled,
    };
    let global_input = match store.load_health_global_context(&plan, &mut global_budget) {
        Ok(input) => input,
        Err(error) => {
            return Err(match analysis_error(&error) {
                Some(error) => fail(error, diagnostics),
                None => RangedHealthError::Store(error),
            });
        }
    };
    let RangeBudget {
        inner: mut global_work,
        ..
    } = global_budget;
    let global_source = GlobalSource::from_health_input(&global_input);
    let global = GlobalIndex::build(&global_source, &mut global_work, &mut is_cancelled)
        .map_err(|error| fail(error, diagnostics.clone()))?;
    diagnostics.work.global_context = global_work.used() as u64;
    let global_context_digest = global_input.digest();

    // Phase 2: ranges, in the requested order, re-splitting overruns.
    let mut queue = order_ranges(plan.ranges.clone(), order)
        .into_iter()
        .map(|range| (range, 0_u8))
        .collect::<VecDeque<_>>();
    let mut next_index = plan.ranges.len() as u32;
    let mut completed = Vec::<RangeRun>::new();
    let mut stop = None::<HealthAnalysisError>;
    while let Some((range, depth)) = queue.pop_front() {
        if is_cancelled() {
            stop = Some(HealthAnalysisError::Cancelled);
            diagnostics.ranges.interrupted += 1;
            continue;
        }
        if let Some(error) = stop
            && (error == HealthAnalysisError::Cancelled || !allow_partial)
        {
            diagnostics.ranges.interrupted += 1;
            continue;
        }
        let key = HealthRangeCheckpointKey::new(
            &plan.plan_digest,
            &range.first_subject_id,
            &range.last_subject_id,
            &global_context_digest,
        );
        if let Some(store) = &checkpoints
            && let Ok(Some(payload)) = store.read(&key)
        {
            diagnostics.ranges.completed += 1;
            diagnostics.ranges.reused += 1;
            diagnostics.checkpoints.reused += 1;
            if let Some(progress) = progress.as_deref_mut() {
                progress(HealthRangeProgress {
                    range: &range,
                    completed: diagnostics.ranges.completed,
                    planned: diagnostics.ranges.total,
                    reused: true,
                });
            }
            completed.push(RangeRun {
                findings: payload.findings,
                subjects_analyzed: payload.subjects_analyzed,
                work_used: payload.work_used,
            });
            continue;
        }
        let step = run_range(
            store,
            &plan,
            &range,
            &global,
            &limits,
            maximum_findings,
            &mut is_cancelled,
        )
        .map_err(RangedHealthError::Store)?;
        match step {
            RangeStep::Completed(run) => {
                diagnostics.work.ranges_total += run.work_used;
                diagnostics.work.ranges_max = diagnostics.work.ranges_max.max(run.work_used);
                diagnostics.ranges.completed += 1;
                if let Some(store) = &checkpoints {
                    let payload = HealthRangeCheckpointPayload {
                        findings: run.findings.clone(),
                        subjects_analyzed: run.subjects_analyzed,
                        work_used: run.work_used,
                    };
                    match store.write(&key, &payload) {
                        Ok(true) => diagnostics.checkpoints.written += 1,
                        Ok(false) | Err(_) => diagnostics.checkpoints.write_failures += 1,
                    }
                }
                if let Some(progress) = progress.as_deref_mut() {
                    progress(HealthRangeProgress {
                        range: &range,
                        completed: diagnostics.ranges.completed,
                        planned: diagnostics.ranges.total,
                        reused: false,
                    });
                }
                completed.push(run);
            }
            RangeStep::Overrun => {
                let halves = if depth < limits.max_resplit_depth
                    && diagnostics.ranges.total < limits.max_ranges
                {
                    let ids = health_range_subject_ids(store, &plan, &range)
                        .map_err(RangedHealthError::Store)?;
                    resplit_health_range(&range, &ids, next_index, depth + 1)
                } else {
                    None
                };
                match halves {
                    Some((left, right)) => {
                        // The parent is replaced by its halves: it no longer
                        // counts as a planned range, the halves do.
                        diagnostics.ranges.resplit += 1;
                        diagnostics.ranges.total += 1;
                        next_index += 2;
                        queue.push_front((right, depth + 1));
                        queue.push_front((left, depth + 1));
                    }
                    None => {
                        diagnostics.ranges.failed += 1;
                        stop.get_or_insert(HealthAnalysisError::ResourceExhausted);
                    }
                }
            }
            RangeStep::Cancelled => {
                diagnostics.ranges.interrupted += 1;
                stop = Some(HealthAnalysisError::Cancelled);
            }
            RangeStep::Integrity => {
                return Err(fail(HealthAnalysisError::Integrity, diagnostics));
            }
        }
    }

    // Phase 3: merge. Ranges are disjoint id intervals, so a duplicate finding
    // id is an integrity failure rather than something to dedupe silently.
    let mut findings = Vec::new();
    for run in completed {
        findings.extend(run.findings);
    }
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    if findings.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(fail(HealthAnalysisError::Integrity, diagnostics));
    }
    if findings.len() > maximum_findings {
        return Err(fail(HealthAnalysisError::ResourceExhausted, diagnostics));
    }

    let incomplete = diagnostics.ranges.failed + diagnostics.ranges.interrupted;
    if incomplete > 0 {
        let error = stop.unwrap_or(HealthAnalysisError::ResourceExhausted);
        if !allow_partial || error == HealthAnalysisError::Cancelled {
            return Err(fail(error, diagnostics));
        }
        diagnostics.partial = true;
        mark_partial(&mut findings, &diagnostics);
    }
    diagnostics.peak_rss_kib = peak_rss_kib();
    Ok(RangedUnusedOutcome {
        findings,
        diagnostics,
        scan: global_input.scan,
        coverage: global_input.coverage,
    })
}

/// Demote every finding of a partial view: the individual finding is exact,
/// but the set it belongs to is not, so an `incomplete_coverage` blocker keeps
/// `counts_by_confidence` from being read as complete.
pub fn mark_partial(findings: &mut [HealthFinding], diagnostics: &HealthRangeDiagnostics) {
    let incomplete = diagnostics.ranges.failed + diagnostics.ranges.interrupted;
    let detail = format!(
        "{incomplete} of {} health ranges were not analysed; usage from those ranges is unknown",
        diagnostics.ranges.total
    );
    for finding in findings {
        finding.blockers.push(FindingBlocker {
            kind: BlockerKind::IncompleteCoverage,
            detail: detail.clone(),
        });
        finding.blockers.sort_by(|left, right| {
            left.kind
                .as_str()
                .cmp(right.kind.as_str())
                .then(left.detail.cmp(&right.detail))
        });
        finding.blockers.dedup();
        finding.confidence = Confidence::Indeterminate;
        finding.fingerprint = finding_fingerprint(finding);
    }
}

/// The trimmed projection the dependency analyzer reads (nodes, edges, sites,
/// profiles, coverage), loaded under its own budget.
pub struct RangedDependencyProjection {
    pub snapshot: GraphSnapshot,
    pub work_used: u64,
}

/// Load the dependency projection of a plain input under one range budget.
///
/// `diagnostics` is the ranged execution state so far (the unused phase that
/// preceded this load); a budget failure reports it unchanged so the failure
/// is attributed to the ranged run, not to a whole-snapshot pass.
pub fn load_dependency_projection(
    store: &Store,
    identity: &HealthInputIdentity,
    limits: &HealthRangeLimits,
    diagnostics: &HealthRangeDiagnostics,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<RangedDependencyProjection, RangedHealthError> {
    let mut budget = RangeBudget {
        inner: HealthAnalysisBudget::new(
            usize::try_from(limits.per_range_work).unwrap_or(usize::MAX),
        ),
        is_cancelled: &mut is_cancelled,
    };
    match store.load_health_dependency_input(identity, &mut budget) {
        Ok((snapshot, work_used)) => Ok(RangedDependencyProjection {
            snapshot,
            work_used,
        }),
        Err(error) => Err(match analysis_error(&error) {
            Some(error) => RangedHealthError::Analysis(Box::new(RangedHealthFailure {
                error,
                diagnostics: diagnostics.clone(),
            })),
            None => RangedHealthError::Store(error),
        }),
    }
}

/// Dependency analysis under one range budget; returns the findings and the
/// steps consumed so the caller can report them.
pub fn analyze_dependencies_ranged(
    snapshot: &GraphSnapshot,
    manifests: &[ManifestIdentity],
    maximum_findings: usize,
    limits: &HealthRangeLimits,
    is_cancelled: impl FnMut() -> bool,
) -> Result<(Vec<HealthFinding>, u64), HealthAnalysisError> {
    let mut budget =
        HealthAnalysisBudget::new(usize::try_from(limits.per_range_work).unwrap_or(usize::MAX));
    let findings = analyze_dependencies_with_budget(
        snapshot,
        manifests,
        maximum_findings,
        &mut budget,
        is_cancelled,
    )?;
    Ok((findings, budget.used() as u64))
}

/// Group the ranges of a plan by split reason, for diagnostics and tests.
#[must_use]
pub fn ranges_by_split_reason(plan: &HealthRangePlan) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::new();
    for range in &plan.ranges {
        let key = match range.split_reason {
            depgraph_store::RangeSplitReason::BudgetReached => "budget_reached",
            depgraph_store::RangeSplitReason::Tail => "tail",
            depgraph_store::RangeSplitReason::ResplitAfterOverrun { .. } => "resplit",
        };
        *counts.entry(key.to_owned()).or_insert(0) += 1;
    }
    counts
}
