//! Pre-split planning for resumable analysis.
//!
//! Static discovery ([`crate::analysis_plan`]) decides which repository files
//! belong to which logical unit.  This module decides, before any worker
//! starts, how each logical unit is executed: which files a worker may emit
//! results for (ownership scope), which files its compiler or loader actually
//! reads (loader scope), which inputs are read for reference only, how much
//! work that is expected to be, why the unit was or was not split, and how
//! many execution units may run at once.
//!
//! The planner is a pure function of the discovery plan, the configured
//! budgets, the adapter's declared splittable boundaries, file sizes, and an
//! ordered list of refinements.  It never reads file contents and never runs
//! project code.  Estimates are relative heuristics; every execution unit
//! keeps its individual deadline, memory, and output limits.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use depgraph_protocol::stable_id_from_value;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    analysis_plan::{AnalysisAdapter, AnalysisPlan, AnalysisUnit, input_dependency_ids},
    config::Config,
};

pub const ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION: &str = "depgraph-analysis-split-plan-v1";

/// A worker that advertises this capability accepts the `split` object in a
/// `depgraph-analysis-unit-v2` request and honours its loader scope: it loads
/// at least `loader.paths`, never fewer, and rejects a binding it cannot
/// validate.  It reports in the [`ANALYSIS_LOADER_SCOPE_PROPERTY`] profile
/// property whether it loaded exactly the requested scope or had to widen it,
/// so the core can tell a real input split from an output-only one.
pub const ANALYSIS_LOADER_SCOPE_CAPABILITY: &str = "analysis-loader-scope-v1";

/// A Go worker that advertises this capability can type-check a bounded set of
/// packages with declaration-level references and analyse function bodies in
/// batches.  Without it the planner keeps the whole-module loader boundary.
pub const ANALYSIS_GO_PACKAGE_LOADER_CAPABILITY: &str = "analysis-go-package-loader-v1";

/// Profile property a loader-scope worker sets to `applied` when it loaded
/// exactly the requested loader scope, or `widened` when it had to load more.
pub const ANALYSIS_LOADER_SCOPE_PROPERTY: &str = "analysis_loader_scope";
pub const ANALYSIS_LOADER_SCOPE_APPLIED: &str = "applied";
pub const ANALYSIS_LOADER_SCOPE_WIDENED: &str = "widened";

const MAX_EXECUTION_UNITS: usize = 1_000_000;
const MAX_REFINEMENTS: usize = 100_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStage {
    Syntax,
    Typed,
    Semantic,
}

impl AnalysisStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::Typed => "typed",
            Self::Semantic => "semantic",
        }
    }

    /// Relative cost of holding one loaded byte in this stage.
    const fn weight_factor(self) -> u64 {
        match self {
            Self::Syntax => 1,
            Self::Typed => 3,
            Self::Semantic => 6,
        }
    }
}

/// What the worker's compiler or loader actually reads.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisLoaderKind {
    /// Exactly `loader.paths` are parsed; other paths are known by name only.
    Files,
    /// The packages in `loader.package_roots` are loaded completely; other
    /// packages contribute references at the declared depth.
    Package,
    /// The whole module is loaded, including every dependency package.
    Module,
    /// The whole project program is loaded, including every referenced file.
    Project,
    /// The whole repository adapter scope is loaded.
    Repository,
}

impl AnalysisLoaderKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::Package => "package",
            Self::Module => "module",
            Self::Project => "project",
            Self::Repository => "repository",
        }
    }

    const fn loads_whole_context(self) -> bool {
        matches!(self, Self::Module | Self::Project | Self::Repository)
    }
}

/// How deeply reference-only inputs are read.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisReferenceDepth {
    /// Reference paths are used for ownership and import resolution only.
    PathsOnly,
    /// Exported declarations and types of reference inputs are needed.
    Declarations,
    /// Function bodies of reference inputs are held at the same time.
    Bodies,
}

impl AnalysisReferenceDepth {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PathsOnly => "paths_only",
            Self::Declarations => "declarations",
            Self::Bodies => "bodies",
        }
    }

    const fn weight_factor(self) -> u64 {
        match self {
            Self::PathsOnly => 0,
            Self::Declarations => 1,
            Self::Bodies => 3,
        }
    }
}

/// The smallest boundary at which an adapter can split a stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSplitGranularity {
    File,
    Package,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSplitKind {
    /// The logical unit executes as one execution unit.
    Whole,
    /// Output is partitioned while the loader still reads the whole context.
    OutputBatch,
    /// The loader input itself is bounded to the batch and its references.
    InputBatch,
    /// Bodies of one package are analysed in batches after a declaration stage.
    StagedBodies,
}

impl AnalysisSplitKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Whole => "whole",
            Self::OutputBatch => "output_batch",
            Self::InputBatch => "input_batch",
            Self::StagedBodies => "staged_bodies",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSplitReason {
    UnitFitsBudget,
    SourceFileBudget,
    SourceByteBudget,
    ContextByteBudget,
    AdapterBoundaryUnsplittable,
    CycleGroupRetained,
    StagedAfterDeclarations,
    Refined,
}

impl AnalysisSplitReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnitFitsBudget => "unit_fits_budget",
            Self::SourceFileBudget => "source_file_budget",
            Self::SourceByteBudget => "source_byte_budget",
            Self::ContextByteBudget => "context_byte_budget",
            Self::AdapterBoundaryUnsplittable => "adapter_boundary_unsplittable",
            Self::CycleGroupRetained => "cycle_group_retained",
            Self::StagedAfterDeclarations => "staged_after_declarations",
            Self::Refined => "refined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisResplitTrigger {
    WorkerTimeout,
    WorkerMemory,
    OutputLimit,
    EstimateExceeded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisUnsplittableReason {
    SingleGranule,
    AdapterBoundary,
    UnknownExecutionUnit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSplitLimitation {
    EstimatesAreHeuristic,
    SourceSizesIncomplete,
    WholeContextLoaderRetained,
    RefinementUnsplittable,
}

impl AnalysisSplitLimitation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EstimatesAreHeuristic => "estimates_are_heuristic",
            Self::SourceSizesIncomplete => "source_sizes_incomplete",
            Self::WholeContextLoaderRetained => "whole_context_loader_retained",
            Self::RefinementUnsplittable => "refinement_unsplittable",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisStageBoundary {
    pub stage: AnalysisStage,
    pub loader_kind: AnalysisLoaderKind,
    pub reference_depth: AnalysisReferenceDepth,
    pub granularity: AnalysisSplitGranularity,
    /// The worker can emit a subset of the unit's results per request.
    pub output_splittable: bool,
    /// The worker can bound its loader to the batch and its references.
    pub input_splittable: bool,
    /// Batches of this stage read bodies of their own files and declarations
    /// of everything else, relying on the preceding stage's results.
    pub staged_bodies: bool,
}

/// The splittable boundaries one worker implementation can honour.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisAdapterBoundary {
    pub adapter: AnalysisAdapter,
    pub id: String,
    pub stages: Vec<AnalysisStageBoundary>,
}

impl AnalysisAdapterBoundary {
    /// Current Go worker: syntax parses selected files; typed and semantic
    /// stages load the complete module and cannot be split.
    pub fn go_module_loader(typed_stage: bool) -> Self {
        let mut stages = vec![AnalysisStageBoundary {
            stage: AnalysisStage::Syntax,
            loader_kind: AnalysisLoaderKind::Files,
            reference_depth: AnalysisReferenceDepth::PathsOnly,
            granularity: AnalysisSplitGranularity::File,
            output_splittable: true,
            input_splittable: true,
            staged_bodies: false,
        }];
        if typed_stage {
            stages.push(AnalysisStageBoundary {
                stage: AnalysisStage::Typed,
                loader_kind: AnalysisLoaderKind::Module,
                reference_depth: AnalysisReferenceDepth::Bodies,
                granularity: AnalysisSplitGranularity::Package,
                output_splittable: false,
                input_splittable: false,
                staged_bodies: false,
            });
        }
        stages.push(AnalysisStageBoundary {
            stage: AnalysisStage::Semantic,
            loader_kind: AnalysisLoaderKind::Module,
            reference_depth: AnalysisReferenceDepth::Bodies,
            granularity: AnalysisSplitGranularity::Package,
            output_splittable: false,
            input_splittable: false,
            staged_bodies: false,
        });
        Self {
            adapter: AnalysisAdapter::Go,
            id: if typed_stage {
                "go-module-loader-typed".to_owned()
            } else {
                "go-module-loader".to_owned()
            },
            stages,
        }
    }

    /// Target Go boundary for issue #463: typed loading is bounded to packages
    /// with declaration references, and a large package's bodies are staged.
    pub fn go_package_loader() -> Self {
        Self {
            adapter: AnalysisAdapter::Go,
            id: "go-package-loader".to_owned(),
            stages: vec![
                AnalysisStageBoundary {
                    stage: AnalysisStage::Syntax,
                    loader_kind: AnalysisLoaderKind::Files,
                    reference_depth: AnalysisReferenceDepth::PathsOnly,
                    granularity: AnalysisSplitGranularity::File,
                    output_splittable: true,
                    input_splittable: true,
                    staged_bodies: false,
                },
                AnalysisStageBoundary {
                    stage: AnalysisStage::Typed,
                    loader_kind: AnalysisLoaderKind::Package,
                    reference_depth: AnalysisReferenceDepth::Declarations,
                    granularity: AnalysisSplitGranularity::Package,
                    output_splittable: true,
                    input_splittable: true,
                    staged_bodies: false,
                },
                AnalysisStageBoundary {
                    stage: AnalysisStage::Semantic,
                    loader_kind: AnalysisLoaderKind::Package,
                    reference_depth: AnalysisReferenceDepth::Declarations,
                    granularity: AnalysisSplitGranularity::File,
                    output_splittable: true,
                    input_splittable: true,
                    staged_bodies: true,
                },
            ],
        }
    }

    /// Current Web worker: syntax parses selected files; the semantic stage
    /// builds the full project program and only partitions its output.
    pub fn web_project_loader() -> Self {
        Self {
            adapter: AnalysisAdapter::Web,
            id: "web-project-loader".to_owned(),
            stages: vec![
                AnalysisStageBoundary {
                    stage: AnalysisStage::Syntax,
                    loader_kind: AnalysisLoaderKind::Files,
                    reference_depth: AnalysisReferenceDepth::PathsOnly,
                    granularity: AnalysisSplitGranularity::File,
                    output_splittable: true,
                    input_splittable: true,
                    staged_bodies: false,
                },
                AnalysisStageBoundary {
                    stage: AnalysisStage::Semantic,
                    loader_kind: AnalysisLoaderKind::Project,
                    reference_depth: AnalysisReferenceDepth::Bodies,
                    granularity: AnalysisSplitGranularity::File,
                    output_splittable: true,
                    input_splittable: false,
                    staged_bodies: false,
                },
            ],
        }
    }

    /// Boundaries of the workers shipped with this core.
    pub fn current_defaults() -> Vec<Self> {
        vec![Self::go_module_loader(true), Self::web_project_loader()]
    }

    /// Select the boundary a negotiated worker can honour, or `None` when the
    /// worker did not negotiate unit execution at all.
    pub fn for_capabilities(adapter: AnalysisAdapter, capabilities: &[String]) -> Option<Self> {
        let has = |name: &str| capabilities.iter().any(|capability| capability == name);
        match adapter {
            AnalysisAdapter::Go if has("analysis-source-batch-v1") => {
                if has(ANALYSIS_GO_PACKAGE_LOADER_CAPABILITY) && has("analysis-unit-typed-v1") {
                    Some(Self::go_package_loader())
                } else {
                    Some(Self::go_module_loader(has("analysis-unit-typed-v1")))
                }
            }
            AnalysisAdapter::Go if has("analysis-unit-v1") => Some(Self::go_module_loader(false)),
            AnalysisAdapter::Web if has("analysis-source-batch-v1") => {
                Some(Self::web_project_loader())
            }
            _ => None,
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty() && self.id.len() <= 128,
            "analysis adapter boundary id is empty or exceeds its limit"
        );
        ensure!(
            !self.stages.is_empty(),
            "analysis adapter boundary {} declares no stages",
            self.id
        );
        for pair in self.stages.windows(2) {
            ensure!(
                pair[0].stage < pair[1].stage,
                "analysis adapter boundary {} stages are not ordered",
                self.id
            );
        }
        for stage in &self.stages {
            ensure!(
                !stage.staged_bodies || stage.stage != AnalysisStage::Syntax,
                "analysis adapter boundary {} stages syntax bodies",
                self.id
            );
            ensure!(
                !stage.staged_bodies || stage.input_splittable,
                "analysis adapter boundary {} stages bodies without an input split",
                self.id
            );
        }
        Ok(())
    }

    pub fn stage(&self, stage: AnalysisStage) -> Option<&AnalysisStageBoundary> {
        self.stages
            .iter()
            .find(|candidate| candidate.stage == stage)
    }

    pub fn stages(&self) -> impl Iterator<Item = AnalysisStage> + '_ {
        self.stages.iter().map(|boundary| boundary.stage)
    }
}

/// Budget inputs that shape the split plan.  They are copied out of the scan
/// configuration so the plan can be explained without the full config.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSplitBudget {
    pub max_concurrent_units: u64,
    pub max_unit_source_files: u64,
    pub max_unit_source_bytes: u64,
    pub max_context_source_bytes: u64,
    pub worker_timeout_seconds: u64,
    pub max_worker_memory_bytes: u64,
    pub max_protocol_bytes: u64,
    pub max_stderr_bytes: u64,
    pub total_budget_seconds: Option<u64>,
}

impl AnalysisSplitBudget {
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_concurrent_units: config.scan.max_concurrent_units as u64,
            max_unit_source_files: config.scan.max_unit_source_files as u64,
            max_unit_source_bytes: config.scan.max_unit_source_bytes,
            max_context_source_bytes: config.scan.max_context_source_bytes,
            worker_timeout_seconds: config.scan.worker_timeout_seconds,
            max_worker_memory_bytes: config.scan.max_worker_memory_bytes,
            max_protocol_bytes: config.scan.max_protocol_bytes as u64,
            max_stderr_bytes: config.scan.max_stderr_bytes as u64,
            total_budget_seconds: config.scan.total_budget_seconds,
        }
    }

    pub fn fingerprint(&self) -> String {
        stable_id_from_value(
            "analysis-split-budget",
            &json!({
                "contract_version": ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION,
                "budget": self,
            }),
        )
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=64).contains(&self.max_concurrent_units),
            "analysis split budget max_concurrent_units must be between 1 and 64"
        );
        ensure!(
            self.max_unit_source_files >= 1,
            "analysis split budget max_unit_source_files must be at least 1"
        );
        ensure!(
            self.max_unit_source_bytes >= 1,
            "analysis split budget max_unit_source_bytes must be at least 1"
        );
        ensure!(
            self.max_context_source_bytes >= self.max_unit_source_bytes,
            "analysis split budget max_context_source_bytes must be at least max_unit_source_bytes"
        );
        ensure!(
            self.worker_timeout_seconds >= 1 && self.max_worker_memory_bytes >= 1,
            "analysis split budget worker limits must be at least 1"
        );
        Ok(())
    }
}

/// A recorded decision to split one execution unit further after its estimate
/// was exceeded.  Refinements are part of the split plan identity so the same
/// discovery plan, budget, and refinement history reproduce the same plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSplitRefinement {
    pub execution_unit_id: String,
    pub trigger: AnalysisResplitTrigger,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisUnsplittableRefinement {
    pub execution_unit_id: String,
    pub trigger: AnalysisResplitTrigger,
    pub reason: AnalysisUnsplittableReason,
}

/// Everything the planner needs beyond the discovery plan.
#[derive(Clone, Debug)]
pub struct AnalysisSplitInput {
    pub budget: AnalysisSplitBudget,
    pub boundaries: Vec<AnalysisAdapterBoundary>,
    /// Source byte sizes by repository-relative path.  Missing entries count
    /// as zero and are reported as a limitation.
    pub sizes: BTreeMap<String, u64>,
    /// Source closure a worker receives as `context_paths`, by unit ID.  Units
    /// without an entry use [`static_context_paths`].
    pub contexts: BTreeMap<String, Vec<String>>,
    pub refinements: Vec<AnalysisSplitRefinement>,
}

impl AnalysisSplitInput {
    pub fn new(budget: AnalysisSplitBudget, boundaries: Vec<AnalysisAdapterBoundary>) -> Self {
        Self {
            budget,
            boundaries,
            sizes: BTreeMap::new(),
            contexts: BTreeMap::new(),
            refinements: Vec::new(),
        }
    }

    pub fn with_sizes(mut self, sizes: BTreeMap<String, u64>) -> Self {
        self.sizes = sizes;
        self
    }

    pub fn with_contexts(mut self, contexts: BTreeMap<String, Vec<String>>) -> Self {
        self.contexts = contexts;
        self
    }

    pub fn with_refinements(mut self, refinements: Vec<AnalysisSplitRefinement>) -> Self {
        self.refinements = refinements;
        self
    }

    fn boundary(&self, adapter: AnalysisAdapter) -> Option<&AnalysisAdapterBoundary> {
        self.boundaries
            .iter()
            .find(|boundary| boundary.adapter == adapter)
    }
}

/// Files whose results this execution unit may emit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisOwnershipScope {
    pub unit_id: String,
    pub unit_root: String,
    /// Strongly connected group over resolved input dependencies.  A cyclic
    /// group must stay in one analysis context; its members are never split
    /// into separate loader contexts by this plan.
    pub context_group_id: String,
    pub context_group_unit_ids: Vec<String>,
    pub cyclic_group: bool,
    pub source_paths: Vec<String>,
    pub package_roots: Vec<String>,
}

/// Files the worker's loader actually reads, and what it reads for reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisLoaderScope {
    pub kind: AnalysisLoaderKind,
    /// Files loaded completely.  Always a superset of the ownership paths.
    pub paths: Vec<String>,
    /// Repository-relative package directories loaded completely.
    pub package_roots: Vec<String>,
    pub reference_depth: AnalysisReferenceDepth,
    /// Files read only at `reference_depth`; disjoint from `paths`.
    pub reference_paths: Vec<String>,
    /// Logical units, other than the owner, whose inputs are referenced.
    pub reference_unit_ids: Vec<String>,
    /// True when `paths` is a strict subset of the unit's full source context,
    /// i.e. the split bounds the loader input rather than only the output.
    pub input_split: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisWorkEstimate {
    pub stage: AnalysisStage,
    pub owned_file_count: u64,
    pub owned_source_bytes: u64,
    pub loader_file_count: u64,
    pub loader_source_bytes: u64,
    pub reference_file_count: u64,
    pub reference_source_bytes: u64,
    pub dependency_closure_units: u64,
    /// Relative ordering weight, not a time or memory prediction.
    pub weight: u64,
    /// The estimate exceeds a budget the adapter boundary cannot split away.
    pub over_budget: bool,
}

/// Individual limits every execution unit keeps regardless of its estimate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisExecutionBudget {
    pub worker_timeout_seconds: u64,
    pub max_worker_memory_bytes: u64,
    pub max_protocol_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_source_files: u64,
    pub max_source_bytes: u64,
    pub max_context_source_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisExecutionUnit {
    pub id: String,
    pub unit_id: String,
    pub adapter: AnalysisAdapter,
    pub stage: AnalysisStage,
    pub batch_index: u64,
    pub batch_count: u64,
    pub split_kind: AnalysisSplitKind,
    pub split_reasons: Vec<AnalysisSplitReason>,
    pub ownership: AnalysisOwnershipScope,
    pub loader: AnalysisLoaderScope,
    pub estimate: AnalysisWorkEstimate,
    pub budget: AnalysisExecutionBudget,
    /// Execution units of the preceding stage of the same logical unit.
    pub prerequisite_ids: Vec<String>,
}

impl AnalysisExecutionUnit {
    /// The request-level binding a loader-scope worker receives.
    pub fn binding(&self, split_plan_id: &str) -> AnalysisSplitBinding {
        AnalysisSplitBinding {
            contract_version: ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION.to_owned(),
            split_plan_id: split_plan_id.to_owned(),
            execution_unit_id: self.id.clone(),
            split_kind: self.split_kind,
            loader: AnalysisLoaderBinding {
                kind: self.loader.kind,
                paths: self.loader.paths.clone(),
                package_roots: self.loader.package_roots.clone(),
                reference_depth: self.loader.reference_depth,
                reference_paths: self.loader.reference_paths.clone(),
                input_split: self.loader.input_split,
            },
        }
    }
}

/// The `split` object of a worker request.  Unit IDs and estimates stay in
/// the core; the worker only needs the loader target and the identity it must
/// echo.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSplitBinding {
    pub contract_version: String,
    pub split_plan_id: String,
    pub execution_unit_id: String,
    pub split_kind: AnalysisSplitKind,
    pub loader: AnalysisLoaderBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisLoaderBinding {
    pub kind: AnalysisLoaderKind,
    pub paths: Vec<String>,
    pub package_roots: Vec<String>,
    pub reference_depth: AnalysisReferenceDepth,
    pub reference_paths: Vec<String>,
    pub input_split: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisExecutionWave {
    pub index: u64,
    pub execution_unit_ids: Vec<String>,
    pub estimated_weight: u64,
}

/// The parallelism decision taken before any worker starts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisParallelism {
    pub max_concurrent_units: u64,
    /// Concurrency the plan can actually use given its prerequisites.
    pub effective_concurrency: u64,
    /// Upper bound on simultaneously admitted worker memory.
    pub admitted_memory_bytes: u64,
    pub waves: Vec<AnalysisExecutionWave>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSplitPlan {
    pub contract_version: String,
    /// Discovery plan identity; unchanged by budgets and refinements.
    pub plan_id: String,
    pub plan_input_digest: String,
    pub budget: AnalysisSplitBudget,
    pub budget_fingerprint: String,
    pub boundaries: Vec<AnalysisAdapterBoundary>,
    pub refinements: Vec<AnalysisSplitRefinement>,
    pub unsplittable_refinements: Vec<AnalysisUnsplittableRefinement>,
    pub split_plan_id: String,
    pub execution_units: Vec<AnalysisExecutionUnit>,
    pub parallelism: AnalysisParallelism,
    pub limitations: Vec<AnalysisSplitLimitation>,
}

impl AnalysisSplitPlan {
    pub fn execution_unit(&self, id: &str) -> Option<&AnalysisExecutionUnit> {
        self.execution_units.iter().find(|unit| unit.id == id)
    }

    pub fn execution_units_for(
        &self,
        unit_id: &str,
        stage: AnalysisStage,
    ) -> Vec<&AnalysisExecutionUnit> {
        self.execution_units
            .iter()
            .filter(|unit| unit.unit_id == unit_id && unit.stage == stage)
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisResplitOutcome {
    Split,
    Unsplittable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSavedResultDisposition {
    /// Identity, inputs, and checkpoint key are unchanged; saved results stay valid.
    Retained,
    /// The execution unit no longer exists; its saved results are discarded.
    Superseded,
    /// A new execution unit without saved results.
    Replacement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSavedResult {
    pub execution_unit_id: String,
    pub disposition: AnalysisSavedResultDisposition,
}

/// The re-split contract: a new split plan for the same discovery plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisResplitPlan {
    pub contract_version: String,
    pub plan_id: String,
    pub previous_split_plan_id: String,
    pub split_plan_id: String,
    pub refinement: AnalysisSplitRefinement,
    pub outcome: AnalysisResplitOutcome,
    pub unsplittable_reason: Option<AnalysisUnsplittableReason>,
    pub superseded_execution_unit_ids: Vec<String>,
    pub replacement_execution_unit_ids: Vec<String>,
    pub retained_execution_unit_ids: Vec<String>,
    pub saved_results: Vec<AnalysisSavedResult>,
    pub plan: AnalysisSplitPlan,
}

/// Measure owned source sizes for every executable unit without reading
/// file contents.  Paths that cannot be measured are omitted so the planner
/// reports incomplete sizes instead of failing the scan.
pub fn measure_source_sizes(root: &Path, plan: &AnalysisPlan) -> Result<BTreeMap<String, u64>> {
    let canonical_root = root
        .canonicalize()
        .context("analysis split repository root is unavailable")?;
    let mut sizes = BTreeMap::new();
    for unit in plan.executable_units() {
        for path in &unit.source_paths {
            if sizes.contains_key(path) {
                continue;
            }
            let absolute = canonical_root.join(path);
            let Ok(metadata) = std::fs::symlink_metadata(&absolute) else {
                continue;
            };
            if metadata.is_file() {
                sizes.insert(path.clone(), metadata.len());
            }
        }
    }
    Ok(sizes)
}

/// The source closure a worker receives as `context_paths`, derived from the
/// plan alone: the unit's own sources plus the sources of every unit in its
/// transitive resolved input dependency closure and of the executable units
/// that own those dependency roots.
pub fn static_context_paths(plan: &AnalysisPlan, unit: &AnalysisUnit) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for id in context_unit_ids(plan, unit) {
        if let Some(member) = plan.unit(&id)
            && member.adapter == unit.adapter
        {
            paths.extend(member.source_paths.iter().cloned());
        }
    }
    paths.extend(unit.source_paths.iter().cloned());
    paths.into_iter().collect()
}

/// Transitive resolved input dependencies, including the unit itself and the
/// executable owner of every dependency root.  A source import can resolve to
/// a package record whose sources are owned by an enclosing module; that
/// module is what the worker actually loads.
fn context_unit_ids(plan: &AnalysisPlan, unit: &AnalysisUnit) -> BTreeSet<String> {
    let mut closure = BTreeSet::from([unit.id.clone()]);
    let mut pending = input_dependency_ids(unit).cloned().collect::<Vec<_>>();
    while let Some(id) = pending.pop() {
        if closure.insert(id.clone())
            && let Some(dependency) = plan.unit(&id)
        {
            pending.extend(input_dependency_ids(dependency).cloned());
        }
    }
    let owners = closure
        .iter()
        .filter_map(|id| plan.unit(id))
        .filter_map(|member| owning_executable(plan, unit.adapter, &member.unit_root))
        .map(|owner| owner.id.clone())
        .collect::<Vec<_>>();
    closure.extend(owners);
    closure
}

fn owning_executable<'a>(
    plan: &'a AnalysisPlan,
    adapter: AnalysisAdapter,
    root: &str,
) -> Option<&'a AnalysisUnit> {
    plan.executable_units()
        .into_iter()
        .filter(|unit| unit.adapter == adapter)
        .filter(|unit| {
            unit.unit_root == "."
                || unit.unit_root == root
                || root.starts_with(&format!("{}/", unit.unit_root))
        })
        .max_by_key(|unit| unit.unit_root.len())
}

/// Strongly connected components over resolved input dependency edges.  The
/// discovery plan's dependency groups also follow workspace-membership and
/// context edges, which make every workspace member topologically cyclic;
/// the analysis context only has to stay together for genuine input cycles.
fn context_groups(plan: &AnalysisPlan) -> BTreeMap<String, ContextGroup> {
    let adjacency = plan
        .units
        .iter()
        .map(|unit| {
            let mut targets = input_dependency_ids(unit)
                .filter(|id| plan.unit(id).is_some())
                .cloned()
                .collect::<Vec<_>>();
            targets.sort();
            targets.dedup();
            (unit.id.clone(), targets)
        })
        .collect::<BTreeMap<_, _>>();
    let mut reverse = BTreeMap::<String, Vec<String>>::new();
    for (from, targets) in &adjacency {
        for target in targets {
            reverse
                .entry(target.clone())
                .or_default()
                .push(from.clone());
        }
    }
    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for id in adjacency.keys() {
        finish_order(id, &adjacency, &mut visited, &mut order);
    }
    visited.clear();
    let mut groups = BTreeMap::new();
    for id in order.into_iter().rev() {
        if visited.contains(&id) {
            continue;
        }
        let mut component = Vec::new();
        collect_component(&id, &reverse, &mut visited, &mut component);
        component.sort();
        let cyclic = component.len() > 1
            || component
                .first()
                .is_some_and(|only| adjacency[only].iter().any(|target| target == only));
        let group = ContextGroup {
            id: stable_id_from_value(
                "analysis-context-group",
                &json!({
                    "contract_version": ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION,
                    "unit_ids": component,
                    "cyclic": cyclic,
                }),
            ),
            unit_ids: component.clone(),
            cyclic,
        };
        for member in component {
            groups.insert(member, group.clone());
        }
    }
    groups
}

fn finish_order(
    id: &str,
    adjacency: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) {
    if !visited.insert(id.to_owned()) {
        return;
    }
    let mut stack = vec![(id.to_owned(), 0_usize)];
    while let Some((current, next)) = stack.last_mut() {
        let targets = &adjacency[current.as_str()];
        if *next < targets.len() {
            let target = targets[*next].clone();
            *next += 1;
            if visited.insert(target.clone()) {
                stack.push((target, 0));
            }
        } else {
            order.push(current.clone());
            stack.pop();
        }
    }
}

fn collect_component(
    id: &str,
    reverse: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
    component: &mut Vec<String>,
) {
    let mut stack = vec![id.to_owned()];
    while let Some(current) = stack.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        if let Some(sources) = reverse.get(&current) {
            stack.extend(sources.iter().cloned());
        }
        component.push(current);
    }
}

#[derive(Clone)]
struct ContextGroup {
    id: String,
    unit_ids: Vec<String>,
    cyclic: bool,
}

/// Build the split plan the shipped worker boundaries would execute, from the
/// discovery plan alone: measured sizes and plan-derived contexts, no worker
/// probe.  `depgraph scan --split-plan` uses this to explain a repository
/// before any scan; the scheduler substitutes the negotiated boundaries and
/// the worker context closure at scan time.
pub fn plan_default_split(
    root: &Path,
    config: &Config,
    plan: &AnalysisPlan,
) -> Result<AnalysisSplitPlan> {
    let adapters = plan
        .executable_units()
        .iter()
        .map(|unit| unit.adapter)
        .collect::<BTreeSet<_>>();
    let boundaries = AnalysisAdapterBoundary::current_defaults()
        .into_iter()
        .filter(|boundary| adapters.contains(&boundary.adapter))
        .collect();
    let input = AnalysisSplitInput::new(AnalysisSplitBudget::from_config(config), boundaries)
        .with_sizes(measure_source_sizes(root, plan)?);
    plan_analysis_split(plan, &input)
}

/// Build the split plan.  The plan is deterministic for the same discovery
/// plan, budget, boundaries, sizes, contexts, and refinement history.
pub fn plan_analysis_split(
    plan: &AnalysisPlan,
    input: &AnalysisSplitInput,
) -> Result<AnalysisSplitPlan> {
    let plan = plan.canonicalize()?;
    input.budget.validate()?;
    ensure!(
        input.refinements.len() <= MAX_REFINEMENTS,
        "analysis split plan exceeds its refinement limit"
    );
    let mut seen_adapters = BTreeSet::new();
    for boundary in &input.boundaries {
        boundary.validate()?;
        ensure!(
            seen_adapters.insert(boundary.adapter),
            "analysis split input declares two boundaries for {}",
            boundary.adapter.as_str()
        );
    }

    let group_by_unit = context_groups(&plan);
    let mut limitations = BTreeSet::from([AnalysisSplitLimitation::EstimatesAreHeuristic]);
    let mut unsplittable_refinements = Vec::new();
    let mut execution_units = Vec::new();
    // The scheduler consumes work adapter-major and stage-major; keep the
    // same order so the parallelism decision matches the admission order.
    let mut adapters = plan
        .executable_units()
        .iter()
        .map(|unit| unit.adapter)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    adapters.sort();
    for adapter in adapters {
        let Some(boundary) = input.boundary(adapter) else {
            continue;
        };
        let units = plan
            .executable_units()
            .into_iter()
            .filter(|unit| unit.adapter == adapter)
            .collect::<Vec<_>>();
        let mut previous_stage_ids = BTreeMap::<String, Vec<String>>::new();
        for stage_boundary in &boundary.stages {
            let mut stage_ids = BTreeMap::<String, Vec<String>>::new();
            for unit in &units {
                let group = group_by_unit.get(unit.id.as_str());
                let context = UnitContext::build(&plan, unit, input, &mut limitations);
                let mut batches = partition(unit, stage_boundary, &input.budget, &context);
                apply_refinements(
                    unit,
                    stage_boundary,
                    input,
                    &context,
                    group,
                    &mut batches,
                    &mut unsplittable_refinements,
                );
                let count = batches.len() as u64;
                let mut ids = Vec::with_capacity(batches.len());
                for (index, batch) in batches.into_iter().enumerate() {
                    let mut execution_unit = build_execution_unit(
                        unit,
                        stage_boundary,
                        &input.budget,
                        &context,
                        group,
                        batch,
                        index as u64,
                        count,
                    );
                    execution_unit.prerequisite_ids = previous_stage_ids
                        .get(&unit.id)
                        .cloned()
                        .unwrap_or_default();
                    if execution_unit.loader.kind.loads_whole_context() {
                        limitations.insert(AnalysisSplitLimitation::WholeContextLoaderRetained);
                    }
                    ids.push(execution_unit.id.clone());
                    execution_units.push(execution_unit);
                }
                stage_ids.insert(unit.id.clone(), ids);
            }
            previous_stage_ids = stage_ids;
        }
    }
    ensure!(
        execution_units.len() <= MAX_EXECUTION_UNITS,
        "analysis split plan exceeds its execution unit limit"
    );
    if !unsplittable_refinements.is_empty() {
        limitations.insert(AnalysisSplitLimitation::RefinementUnsplittable);
    }
    let parallelism = decide_parallelism(&execution_units, &input.budget);
    let budget_fingerprint = input.budget.fingerprint();
    let split_plan_id = stable_id_from_value(
        "analysis-split-plan",
        &json!({
            "contract_version": ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION,
            "plan_id": plan.plan_id,
            "budget_fingerprint": budget_fingerprint,
            "boundaries": input.boundaries,
            "refinements": input.refinements,
            "execution_unit_ids": execution_units.iter().map(|unit| unit.id.as_str()).collect::<Vec<_>>(),
        }),
    );
    Ok(AnalysisSplitPlan {
        contract_version: ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION.to_owned(),
        plan_id: plan.plan_id.clone(),
        plan_input_digest: plan.input_digest.clone(),
        budget: input.budget.clone(),
        budget_fingerprint,
        boundaries: input.boundaries.clone(),
        refinements: input.refinements.clone(),
        unsplittable_refinements,
        split_plan_id,
        execution_units,
        parallelism,
        limitations: limitations.into_iter().collect(),
    })
}

/// Re-plan one execution unit whose estimate was exceeded.  The discovery
/// plan ID and every unit input fingerprint are unchanged; only the split
/// plan ID and the execution units derived from the refined unit change.
pub fn resplit_execution_unit(
    plan: &AnalysisPlan,
    current: &AnalysisSplitPlan,
    input: &AnalysisSplitInput,
    execution_unit_id: &str,
    trigger: AnalysisResplitTrigger,
) -> Result<AnalysisResplitPlan> {
    let canonical = plan.canonicalize()?;
    ensure!(
        canonical.plan_id == current.plan_id,
        "analysis re-split requires the discovery plan the split plan was built from"
    );
    let refinement = AnalysisSplitRefinement {
        execution_unit_id: execution_unit_id.to_owned(),
        trigger,
    };
    let previous_ids = current
        .execution_units
        .iter()
        .map(|unit| unit.id.clone())
        .collect::<BTreeSet<_>>();
    if !previous_ids.contains(execution_unit_id) {
        bail!("analysis re-split target is not an execution unit of the current split plan");
    }
    let mut refinements = current.refinements.clone();
    refinements.push(refinement.clone());
    let next_input = AnalysisSplitInput {
        refinements,
        ..input.clone()
    };
    let next = plan_analysis_split(&canonical, &next_input)?;
    let unsplittable = next
        .unsplittable_refinements
        .iter()
        .find(|entry| entry.execution_unit_id == execution_unit_id)
        .map(|entry| entry.reason);
    if let Some(reason) = unsplittable {
        let retained = previous_ids.iter().cloned().collect::<Vec<_>>();
        return Ok(AnalysisResplitPlan {
            contract_version: ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION.to_owned(),
            plan_id: current.plan_id.clone(),
            previous_split_plan_id: current.split_plan_id.clone(),
            split_plan_id: current.split_plan_id.clone(),
            refinement,
            outcome: AnalysisResplitOutcome::Unsplittable,
            unsplittable_reason: Some(reason),
            superseded_execution_unit_ids: Vec::new(),
            replacement_execution_unit_ids: Vec::new(),
            saved_results: retained
                .iter()
                .map(|id| AnalysisSavedResult {
                    execution_unit_id: id.clone(),
                    disposition: AnalysisSavedResultDisposition::Retained,
                })
                .collect(),
            retained_execution_unit_ids: retained,
            plan: current.clone(),
        });
    }
    let next_ids = next
        .execution_units
        .iter()
        .map(|unit| unit.id.clone())
        .collect::<BTreeSet<_>>();
    let superseded = previous_ids
        .difference(&next_ids)
        .cloned()
        .collect::<Vec<_>>();
    let replacements = next_ids
        .difference(&previous_ids)
        .cloned()
        .collect::<Vec<_>>();
    let retained = previous_ids
        .intersection(&next_ids)
        .cloned()
        .collect::<Vec<_>>();
    let mut saved_results = Vec::new();
    for id in &retained {
        saved_results.push(AnalysisSavedResult {
            execution_unit_id: id.clone(),
            disposition: AnalysisSavedResultDisposition::Retained,
        });
    }
    for id in &superseded {
        saved_results.push(AnalysisSavedResult {
            execution_unit_id: id.clone(),
            disposition: AnalysisSavedResultDisposition::Superseded,
        });
    }
    for id in &replacements {
        saved_results.push(AnalysisSavedResult {
            execution_unit_id: id.clone(),
            disposition: AnalysisSavedResultDisposition::Replacement,
        });
    }
    saved_results.sort_by(|left, right| left.execution_unit_id.cmp(&right.execution_unit_id));
    Ok(AnalysisResplitPlan {
        contract_version: ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION.to_owned(),
        plan_id: current.plan_id.clone(),
        previous_split_plan_id: current.split_plan_id.clone(),
        split_plan_id: next.split_plan_id.clone(),
        refinement,
        outcome: AnalysisResplitOutcome::Split,
        unsplittable_reason: None,
        superseded_execution_unit_ids: superseded,
        replacement_execution_unit_ids: replacements,
        retained_execution_unit_ids: retained,
        saved_results,
        plan: next,
    })
}

struct UnitContext {
    context_paths: Vec<String>,
    reference_unit_ids: Vec<String>,
    sizes: BTreeMap<String, u64>,
}

impl UnitContext {
    fn build(
        plan: &AnalysisPlan,
        unit: &AnalysisUnit,
        input: &AnalysisSplitInput,
        limitations: &mut BTreeSet<AnalysisSplitLimitation>,
    ) -> Self {
        let mut context_paths = input
            .contexts
            .get(&unit.id)
            .cloned()
            .unwrap_or_else(|| static_context_paths(plan, unit));
        context_paths.extend(unit.source_paths.iter().cloned());
        context_paths.sort();
        context_paths.dedup();
        let reference_unit_ids = context_unit_ids(plan, unit)
            .into_iter()
            .filter(|id| id != &unit.id)
            .collect::<Vec<_>>();
        let mut sizes = BTreeMap::new();
        for path in &context_paths {
            match input.sizes.get(path) {
                Some(size) => {
                    sizes.insert(path.clone(), *size);
                }
                None => {
                    limitations.insert(AnalysisSplitLimitation::SourceSizesIncomplete);
                    sizes.insert(path.clone(), 0);
                }
            }
        }
        Self {
            context_paths,
            reference_unit_ids,
            sizes,
        }
    }

    fn size(&self, path: &str) -> u64 {
        self.sizes.get(path).copied().unwrap_or_default()
    }

    fn total(&self, paths: &[String]) -> u64 {
        paths.iter().map(|path| self.size(path)).sum()
    }
}

/// One ownership batch before it becomes an execution unit.
struct Batch {
    granules: Vec<Granule>,
    reasons: BTreeSet<AnalysisSplitReason>,
}

impl Batch {
    fn paths(&self) -> Vec<String> {
        self.granules
            .iter()
            .flat_map(|granule| granule.paths.iter().cloned())
            .collect()
    }

    fn package_roots(&self) -> Vec<String> {
        let mut roots = self
            .granules
            .iter()
            .map(|granule| granule.package_root.clone())
            .collect::<Vec<_>>();
        roots.sort();
        roots.dedup();
        roots
    }
}

#[derive(Clone)]
struct Granule {
    package_root: String,
    paths: Vec<String>,
    bytes: u64,
}

fn package_root_of(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((directory, _)) => directory.to_owned(),
        None => ".".to_owned(),
    }
}

fn granules(
    unit: &AnalysisUnit,
    granularity: AnalysisSplitGranularity,
    context: &UnitContext,
) -> Vec<Granule> {
    match granularity {
        AnalysisSplitGranularity::File => unit
            .source_paths
            .iter()
            .map(|path| Granule {
                package_root: package_root_of(path),
                paths: vec![path.clone()],
                bytes: context.size(path),
            })
            .collect(),
        AnalysisSplitGranularity::Package => {
            let mut by_root = BTreeMap::<String, Granule>::new();
            for path in &unit.source_paths {
                let root = package_root_of(path);
                let granule = by_root.entry(root.clone()).or_insert_with(|| Granule {
                    package_root: root,
                    paths: Vec::new(),
                    bytes: 0,
                });
                granule.paths.push(path.clone());
                granule.bytes += context.size(path);
            }
            by_root.into_values().collect()
        }
    }
}

fn partition(
    unit: &AnalysisUnit,
    boundary: &AnalysisStageBoundary,
    budget: &AnalysisSplitBudget,
    context: &UnitContext,
) -> Vec<Batch> {
    let granules = granules(unit, boundary.granularity, context);
    if granules.is_empty() || !(boundary.output_splittable || boundary.input_splittable) {
        return vec![Batch {
            granules,
            reasons: BTreeSet::new(),
        }];
    }
    let mut batches = Vec::<Batch>::new();
    let mut current = Vec::<Granule>::new();
    let mut current_files = 0_u64;
    let mut current_bytes = 0_u64;
    let mut reasons = BTreeSet::new();
    for granule in granules {
        let files = granule.paths.len() as u64;
        let exceeds_files = current_files + files > budget.max_unit_source_files;
        let exceeds_bytes = current_bytes + granule.bytes > budget.max_unit_source_bytes;
        if !current.is_empty() && (exceeds_files || exceeds_bytes) {
            if exceeds_files {
                reasons.insert(AnalysisSplitReason::SourceFileBudget);
            }
            if exceeds_bytes {
                reasons.insert(AnalysisSplitReason::SourceByteBudget);
            }
            batches.push(Batch {
                granules: std::mem::take(&mut current),
                reasons: BTreeSet::new(),
            });
            current_files = 0;
            current_bytes = 0;
        }
        current_files += files;
        current_bytes += granule.bytes;
        current.push(granule);
    }
    if !current.is_empty() {
        batches.push(Batch {
            granules: current,
            reasons: BTreeSet::new(),
        });
    }
    if batches.len() > 1 {
        for batch in &mut batches {
            batch.reasons.extend(reasons.iter().copied());
        }
    }
    batches
}

#[allow(clippy::too_many_arguments)]
fn apply_refinements(
    unit: &AnalysisUnit,
    boundary: &AnalysisStageBoundary,
    input: &AnalysisSplitInput,
    context: &UnitContext,
    group: Option<&ContextGroup>,
    batches: &mut Vec<Batch>,
    unsplittable: &mut Vec<AnalysisUnsplittableRefinement>,
) {
    for refinement in &input.refinements {
        let count = batches.len() as u64;
        let position = batches.iter().enumerate().position(|(index, batch)| {
            build_execution_unit(
                unit,
                boundary,
                &input.budget,
                context,
                group,
                Batch {
                    granules: batch.granules.clone(),
                    reasons: batch.reasons.clone(),
                },
                index as u64,
                count,
            )
            .id == refinement.execution_unit_id
        });
        let Some(position) = position else {
            continue;
        };
        if !(boundary.output_splittable || boundary.input_splittable) {
            unsplittable.push(AnalysisUnsplittableRefinement {
                execution_unit_id: refinement.execution_unit_id.clone(),
                trigger: refinement.trigger,
                reason: AnalysisUnsplittableReason::AdapterBoundary,
            });
            continue;
        }
        let batch = &batches[position];
        if batch.granules.len() < 2 {
            unsplittable.push(AnalysisUnsplittableRefinement {
                execution_unit_id: refinement.execution_unit_id.clone(),
                trigger: refinement.trigger,
                reason: AnalysisUnsplittableReason::SingleGranule,
            });
            continue;
        }
        let total = batch
            .granules
            .iter()
            .map(|granule| granule.bytes)
            .sum::<u64>();
        let mut cumulative = 0_u64;
        let mut split_at = 0_usize;
        for (index, granule) in batch.granules.iter().enumerate() {
            cumulative += granule.bytes;
            split_at = index + 1;
            if cumulative.saturating_mul(2) >= total {
                break;
            }
        }
        let split_at = split_at.clamp(1, batch.granules.len() - 1);
        let mut reasons = batch.reasons.clone();
        reasons.insert(AnalysisSplitReason::Refined);
        let removed = batches.remove(position);
        let (head, tail) = removed.granules.split_at(split_at);
        batches.insert(
            position,
            Batch {
                granules: tail.to_vec(),
                reasons: reasons.clone(),
            },
        );
        batches.insert(
            position,
            Batch {
                granules: head.to_vec(),
                reasons,
            },
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn build_execution_unit(
    unit: &AnalysisUnit,
    boundary: &AnalysisStageBoundary,
    budget: &AnalysisSplitBudget,
    context: &UnitContext,
    group: Option<&ContextGroup>,
    batch: Batch,
    batch_index: u64,
    batch_count: u64,
) -> AnalysisExecutionUnit {
    let owned_paths = batch.paths();
    let owned_roots = batch.package_roots();
    let (loader_paths, loader_roots) = if boundary.loader_kind.loads_whole_context() {
        let mut roots = BTreeSet::from([unit.unit_root.clone()]);
        roots.extend(
            context
                .context_paths
                .iter()
                .map(|path| package_root_of(path)),
        );
        (
            context.context_paths.clone(),
            roots.into_iter().collect::<Vec<_>>(),
        )
    } else {
        (owned_paths.clone(), owned_roots.clone())
    };
    let loader_set = loader_paths.iter().collect::<BTreeSet<_>>();
    let reference_paths = context
        .context_paths
        .iter()
        .filter(|path| !loader_set.contains(path))
        .cloned()
        .collect::<Vec<_>>();
    let input_split = loader_paths.len() < context.context_paths.len();
    let cyclic_group = group.is_some_and(|group| group.cyclic && group.unit_ids.len() > 1);

    let owned_bytes = context.total(&owned_paths);
    let loader_bytes = context.total(&loader_paths);
    let reference_bytes = context.total(&reference_paths);
    // Budget reasons first: why the ownership was partitioned, or why a
    // partition was impossible. Context reasons follow: what the loader must
    // keep together regardless of the budget.
    let mut reasons = batch.reasons;
    let exceeds_files = owned_paths.len() as u64 > budget.max_unit_source_files;
    let exceeds_bytes = owned_bytes > budget.max_unit_source_bytes;
    let exceeds_context = loader_bytes > budget.max_context_source_bytes;
    let over_budget = exceeds_files || exceeds_bytes || exceeds_context;
    if exceeds_files {
        reasons.insert(AnalysisSplitReason::SourceFileBudget);
    }
    if exceeds_bytes {
        reasons.insert(AnalysisSplitReason::SourceByteBudget);
    }
    if exceeds_context {
        reasons.insert(AnalysisSplitReason::ContextByteBudget);
    }
    if over_budget {
        // The partition could not go below the budget: either the adapter
        // cannot split this stage, or one granule alone exceeds the budget.
        reasons.insert(AnalysisSplitReason::AdapterBoundaryUnsplittable);
    } else if batch_count <= 1 {
        reasons.insert(AnalysisSplitReason::UnitFitsBudget);
    }
    if cyclic_group && boundary.reference_depth != AnalysisReferenceDepth::PathsOnly {
        reasons.insert(AnalysisSplitReason::CycleGroupRetained);
    }
    let split_kind = if batch_count <= 1 {
        AnalysisSplitKind::Whole
    } else if boundary.staged_bodies {
        reasons.insert(AnalysisSplitReason::StagedAfterDeclarations);
        AnalysisSplitKind::StagedBodies
    } else if input_split {
        AnalysisSplitKind::InputBatch
    } else {
        AnalysisSplitKind::OutputBatch
    };
    let owned_file_count = owned_paths.len() as u64;
    let loader_file_count = loader_paths.len() as u64;
    let reference_file_count = reference_paths.len() as u64;
    let weight = loader_bytes
        .saturating_mul(boundary.stage.weight_factor())
        .saturating_add(reference_bytes.saturating_mul(boundary.reference_depth.weight_factor()))
        .saturating_add(owned_file_count.saturating_mul(boundary.stage.weight_factor()));
    let id = stable_id_from_value(
        "analysis-execution-unit",
        &json!({
            "contract_version": ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION,
            "unit_id": unit.id,
            "stage": boundary.stage,
            "ownership": owned_paths,
            "loader_kind": boundary.loader_kind,
            "loader_paths": loader_paths,
            "reference_depth": boundary.reference_depth,
        }),
    );
    AnalysisExecutionUnit {
        id,
        unit_id: unit.id.clone(),
        adapter: unit.adapter,
        stage: boundary.stage,
        batch_index,
        batch_count,
        split_kind,
        split_reasons: reasons.into_iter().collect(),
        ownership: AnalysisOwnershipScope {
            unit_id: unit.id.clone(),
            unit_root: unit.unit_root.clone(),
            context_group_id: group.map(|group| group.id.clone()).unwrap_or_default(),
            context_group_unit_ids: group
                .map(|group| group.unit_ids.clone())
                .unwrap_or_else(|| vec![unit.id.clone()]),
            cyclic_group,
            source_paths: owned_paths,
            package_roots: owned_roots,
        },
        loader: AnalysisLoaderScope {
            kind: boundary.loader_kind,
            paths: loader_paths,
            package_roots: loader_roots,
            reference_depth: boundary.reference_depth,
            reference_paths,
            reference_unit_ids: context.reference_unit_ids.clone(),
            input_split,
        },
        estimate: AnalysisWorkEstimate {
            stage: boundary.stage,
            owned_file_count,
            owned_source_bytes: owned_bytes,
            loader_file_count,
            loader_source_bytes: loader_bytes,
            reference_file_count,
            reference_source_bytes: reference_bytes,
            dependency_closure_units: context.reference_unit_ids.len() as u64,
            weight,
            over_budget,
        },
        budget: AnalysisExecutionBudget {
            worker_timeout_seconds: budget.worker_timeout_seconds,
            max_worker_memory_bytes: budget.max_worker_memory_bytes,
            max_protocol_bytes: budget.max_protocol_bytes,
            max_stderr_bytes: budget.max_stderr_bytes,
            max_source_files: budget.max_unit_source_files,
            max_source_bytes: budget.max_unit_source_bytes,
            max_context_source_bytes: budget.max_context_source_bytes,
        },
        prerequisite_ids: Vec::new(),
    }
}

fn decide_parallelism(
    units: &[AnalysisExecutionUnit],
    budget: &AnalysisSplitBudget,
) -> AnalysisParallelism {
    let limit = budget.max_concurrent_units.max(1) as usize;
    let mut wave_of = BTreeMap::<&str, usize>::new();
    let mut waves = Vec::<AnalysisExecutionWave>::new();
    for unit in units {
        let earliest = unit
            .prerequisite_ids
            .iter()
            .filter_map(|id| wave_of.get(id.as_str()))
            .max()
            .map_or(0, |wave| wave + 1);
        let target = match waves.last() {
            Some(last)
                if (last.index as usize) >= earliest && last.execution_unit_ids.len() < limit =>
            {
                waves.len() - 1
            }
            Some(last) => {
                let index = ((last.index as usize) + 1).max(earliest);
                waves.push(AnalysisExecutionWave {
                    index: index as u64,
                    execution_unit_ids: Vec::new(),
                    estimated_weight: 0,
                });
                waves.len() - 1
            }
            None => {
                waves.push(AnalysisExecutionWave {
                    index: earliest as u64,
                    execution_unit_ids: Vec::new(),
                    estimated_weight: 0,
                });
                0
            }
        };
        waves[target].execution_unit_ids.push(unit.id.clone());
        waves[target].estimated_weight = waves[target]
            .estimated_weight
            .saturating_add(unit.estimate.weight);
        wave_of.insert(unit.id.as_str(), waves[target].index as usize);
    }
    let effective = waves
        .iter()
        .map(|wave| wave.execution_unit_ids.len())
        .max()
        .unwrap_or(0)
        .min(limit) as u64;
    AnalysisParallelism {
        max_concurrent_units: budget.max_concurrent_units,
        effective_concurrency: effective,
        admitted_memory_bytes: budget
            .max_worker_memory_bytes
            .saturating_mul(effective.max(1)),
        waves,
    }
}
