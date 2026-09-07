//! Contract tests for `depgraph-analysis-split-plan-v1`.
//!
//! The public synthetic fixture under `fixtures/analysis-split-plan-v1`
//! contains a Go workspace with a module that imports another module, a
//! two-module cycle, a module outside the workspace, a single large package
//! (large through the fixture's synthetic size table), and a nested pnpm
//! workspace whose application imports a workspace package.
//!
//! Set `DEPGRAPH_UPDATE_FIXTURES=1` to rewrite the expected projection.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use depgraph_core::{
    Config,
    analysis_plan::{AnalysisPlan, plan_analysis_units},
    analysis_split::{
        ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION, AnalysisAdapterBoundary, AnalysisExecutionUnit,
        AnalysisLoaderKind, AnalysisReferenceDepth, AnalysisResplitOutcome, AnalysisResplitTrigger,
        AnalysisSavedResultDisposition, AnalysisSplitBudget, AnalysisSplitInput, AnalysisSplitKind,
        AnalysisSplitLimitation, AnalysisSplitPlan, AnalysisSplitReason, AnalysisStage,
        AnalysisUnsplittableReason, measure_source_sizes, plan_analysis_split,
        resplit_execution_unit, static_context_paths,
    },
};
use serde_json::{Value, json};

const SPLIT_PLAN_SCHEMA: &str =
    include_str!("../../../schemas/depgraph-analysis-split-plan-v1.schema.json");

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/analysis-split-plan-v1")
}

fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let destination = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

/// A checkout of the fixture repository at a fresh temporary path.
struct Checkout {
    _directory: tempfile::TempDir,
    root: PathBuf,
}

impl Checkout {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("repository");
        copy_tree(&fixture_root().join("repository"), &root)?;
        Ok(Self {
            _directory: directory,
            root,
        })
    }

    fn discover(&self, config: &Config) -> Result<AnalysisPlan> {
        plan_analysis_units(&self.root, config, None)
    }

    /// Measured sizes overridden by the fixture's synthetic size table.
    fn sizes(&self, plan: &AnalysisPlan) -> Result<BTreeMap<String, u64>> {
        let mut sizes = measure_source_sizes(&self.root, plan)?;
        let table: Value =
            serde_json::from_str(&fs::read_to_string(fixture_root().join("sizes.json"))?)?;
        for (path, size) in table["sizes"].as_object().context("sizes table")? {
            sizes.insert(path.clone(), size.as_u64().context("size")?);
        }
        Ok(sizes)
    }
}

fn budget(configure: impl FnOnce(&mut Config)) -> (Config, AnalysisSplitBudget) {
    let mut config = Config::default();
    configure(&mut config);
    let budget = AnalysisSplitBudget::from_config(&config);
    (config, budget)
}

fn split(
    checkout: &Checkout,
    plan: &AnalysisPlan,
    budget: &AnalysisSplitBudget,
    boundaries: Vec<AnalysisAdapterBoundary>,
) -> Result<(AnalysisSplitPlan, AnalysisSplitInput)> {
    let input =
        AnalysisSplitInput::new(budget.clone(), boundaries).with_sizes(checkout.sizes(plan)?);
    Ok((plan_analysis_split(plan, &input)?, input))
}

fn unit_id(plan: &AnalysisPlan, unit_root: &str, adapter: &str) -> String {
    plan.executable_units()
        .into_iter()
        .find(|unit| unit.unit_root == unit_root && unit.adapter.as_str() == adapter)
        .map(|unit| unit.id.clone())
        .unwrap_or_else(|| panic!("fixture unit {adapter} {unit_root}"))
}

fn units<'a>(
    split_plan: &'a AnalysisSplitPlan,
    plan: &AnalysisPlan,
    unit_root: &str,
    adapter: &str,
    stage: AnalysisStage,
) -> Vec<&'a AnalysisExecutionUnit> {
    split_plan.execution_units_for(&unit_id(plan, unit_root, adapter), stage)
}

fn only<'a>(
    split_plan: &'a AnalysisSplitPlan,
    plan: &AnalysisPlan,
    unit_root: &str,
    adapter: &str,
    stage: AnalysisStage,
) -> &'a AnalysisExecutionUnit {
    let found = units(split_plan, plan, unit_root, adapter, stage);
    assert_eq!(
        found.len(),
        1,
        "{adapter} {unit_root} {stage:?} has one execution unit"
    );
    found[0]
}

/// Content-independent view used for the checked-in expectation.  Discovery
/// and split plan IDs bind file contents and the full configuration; they
/// are covered by the determinism test instead.
fn projection(split_plan: &AnalysisSplitPlan, plan: &AnalysisPlan) -> Value {
    let root_of = |id: &str| {
        plan.unit(id)
            .map(|unit| {
                format!(
                    "{}:{}:{}",
                    unit.adapter.as_str(),
                    serde_json::to_value(unit.kind).unwrap().as_str().unwrap(),
                    unit.unit_root
                )
            })
            .unwrap_or_else(|| id.to_owned())
    };
    let label = |unit: &AnalysisExecutionUnit| {
        format!(
            "{}:{}:{}/{}",
            root_of(&unit.unit_id),
            unit.stage.as_str(),
            unit.batch_index,
            unit.batch_count
        )
    };
    let by_id = split_plan
        .execution_units
        .iter()
        .map(|unit| (unit.id.as_str(), label(unit)))
        .collect::<BTreeMap<_, _>>();
    json!({
        "budget": split_plan.budget,
        "boundaries": split_plan.boundaries.iter().map(|boundary| boundary.id.as_str()).collect::<Vec<_>>(),
        "limitations": split_plan.limitations,
        "parallelism": {
            "max_concurrent_units": split_plan.parallelism.max_concurrent_units,
            "effective_concurrency": split_plan.parallelism.effective_concurrency,
            "admitted_memory_bytes": split_plan.parallelism.admitted_memory_bytes,
            "waves": split_plan.parallelism.waves.iter().map(|wave| json!({
                "index": wave.index,
                "estimated_weight": wave.estimated_weight,
                "execution_units": wave.execution_unit_ids.iter().map(|id| by_id[id.as_str()].clone()).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        },
        "execution_units": split_plan.execution_units.iter().map(|unit| json!({
            "id": unit.id,
            "label": label(unit),
            "split_kind": unit.split_kind,
            "split_reasons": unit.split_reasons,
            "ownership": {
                "unit_root": unit.ownership.unit_root,
                "context_group": unit.ownership.context_group_unit_ids.iter().map(|id| root_of(id)).collect::<Vec<_>>(),
                "cyclic_group": unit.ownership.cyclic_group,
                "source_paths": unit.ownership.source_paths,
                "package_roots": unit.ownership.package_roots,
            },
            "loader": {
                "kind": unit.loader.kind,
                "paths": unit.loader.paths,
                "package_roots": unit.loader.package_roots,
                "reference_depth": unit.loader.reference_depth,
                "reference_paths": unit.loader.reference_paths,
                "reference_units": unit.loader.reference_unit_ids.iter().map(|id| root_of(id)).collect::<Vec<_>>(),
                "input_split": unit.loader.input_split,
            },
            "estimate": unit.estimate,
            "budget": unit.budget,
            "prerequisites": unit.prerequisite_ids.iter().map(|id| by_id[id.as_str()].clone()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn scenarios(
    checkout: &Checkout,
) -> Result<BTreeMap<&'static str, (AnalysisPlan, AnalysisSplitPlan)>> {
    let mut scenarios = BTreeMap::new();
    let (config, default_budget) = budget(|_| {});
    let plan = checkout.discover(&config)?;
    let (current, _) = split(
        checkout,
        &plan,
        &default_budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    scenarios.insert("current-workers-default-budget", (plan.clone(), current));
    let (_, file_budget) = budget(|config| {
        config.scan.max_unit_source_files = 2;
        config.scan.max_concurrent_units = 3;
    });
    let (files, _) = split(
        checkout,
        &plan,
        &file_budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    scenarios.insert("current-workers-two-file-budget", (plan.clone(), files));
    let (staged, _) = split(
        checkout,
        &plan,
        &default_budget,
        vec![
            AnalysisAdapterBoundary::go_package_loader(),
            AnalysisAdapterBoundary::web_project_loader(),
        ],
    )?;
    scenarios.insert("go-package-loader-default-budget", (plan, staged));
    Ok(scenarios)
}

#[test]
fn split_plan_projection_matches_the_public_fixture_expectation() -> Result<()> {
    let checkout = Checkout::new()?;
    let actual = scenarios(&checkout)?
        .into_iter()
        .map(|(name, (plan, split_plan))| (name, projection(&split_plan, &plan)))
        .collect::<BTreeMap<_, _>>();
    let actual = serde_json::to_value(actual)?;
    let expected_path = fixture_root().join("expected/split-plans.json");
    if std::env::var_os("DEPGRAPH_UPDATE_FIXTURES").is_some() {
        fs::create_dir_all(expected_path.parent().unwrap())?;
        fs::write(
            &expected_path,
            format!("{}\n", serde_json::to_string_pretty(&actual)?),
        )?;
    }
    let expected: Value = serde_json::from_str(&fs::read_to_string(&expected_path)?)?;
    assert_eq!(
        actual, expected,
        "split plan projection differs from fixtures/analysis-split-plan-v1/expected/split-plans.json"
    );
    Ok(())
}

#[test]
fn same_input_produces_the_same_split_plan_across_checkouts_and_runs() -> Result<()> {
    let first = Checkout::new()?;
    let second = Checkout::new()?;
    let (config, budget) = budget(|_| {});
    let first_plan = first.discover(&config)?;
    let second_plan = second.discover(&config)?;
    assert_eq!(first_plan.plan_id, second_plan.plan_id);
    let (first_split, input) = split(
        &first,
        &first_plan,
        &budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    let (second_split, _) = split(
        &second,
        &second_plan,
        &budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    assert_eq!(
        serde_json::to_value(&first_split)?,
        serde_json::to_value(&second_split)?
    );
    assert_eq!(
        first_split.split_plan_id,
        plan_analysis_split(&first_plan, &input)?.split_plan_id
    );
    for unit in &first_split.execution_units {
        assert!(unit.id.starts_with("analysis-execution-unit:sha256:"));
        assert!(!unit.id.contains(first.root.to_str().unwrap()));
        for path in unit.loader.paths.iter().chain(&unit.ownership.source_paths) {
            assert!(!path.starts_with('/'), "{path} is repository relative");
        }
    }
    let ids = first_split
        .execution_units
        .iter()
        .map(|unit| unit.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids.len(),
        first_split.execution_units.len(),
        "execution unit IDs are unique"
    );
    Ok(())
}

#[test]
fn budget_change_changes_the_split_plan_but_not_discovery_or_input_fingerprints() -> Result<()> {
    let checkout = Checkout::new()?;
    let (config, default_budget) = budget(|_| {});
    let (_, file_budget) = budget(|config| config.scan.max_unit_source_files = 2);
    let plan = checkout.discover(&config)?;
    let (default_split, _) = split(
        &checkout,
        &plan,
        &default_budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    let (file_split, _) = split(
        &checkout,
        &plan,
        &file_budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;

    assert_eq!(default_split.plan_id, plan.plan_id);
    assert_eq!(file_split.plan_id, plan.plan_id);
    assert_ne!(
        default_split.budget_fingerprint,
        file_split.budget_fingerprint
    );
    assert_ne!(default_split.split_plan_id, file_split.split_plan_id);

    // The documented difference: the three-file Web application is one
    // syntax batch by default and two under the two-file budget; its
    // semantic stage keeps the whole project loader and only partitions output.
    assert_eq!(
        units(
            &default_split,
            &plan,
            "frontend/apps/web",
            "web",
            AnalysisStage::Syntax
        )
        .len(),
        1
    );
    let syntax = units(
        &file_split,
        &plan,
        "frontend/apps/web",
        "web",
        AnalysisStage::Syntax,
    );
    assert_eq!(syntax.len(), 2);
    assert!(syntax.iter().all(|unit| {
        unit.split_reasons
            .contains(&AnalysisSplitReason::SourceFileBudget)
    }));
    assert!(
        syntax
            .iter()
            .all(|unit| unit.split_kind == AnalysisSplitKind::InputBatch)
    );
    let semantic = units(
        &file_split,
        &plan,
        "frontend/apps/web",
        "web",
        AnalysisStage::Semantic,
    );
    assert_eq!(semantic.len(), 2);
    assert!(
        semantic
            .iter()
            .all(|unit| unit.split_kind == AnalysisSplitKind::OutputBatch)
    );
    assert_eq!(
        units(
            &file_split,
            &plan,
            "services/big",
            "go",
            AnalysisStage::Syntax
        )
        .len(),
        4
    );

    // Ownership never changes with the budget; the union of owned paths is
    // the unit's source set in every scenario.
    for stage in [AnalysisStage::Syntax, AnalysisStage::Semantic] {
        let owned = units(&file_split, &plan, "services/big", "go", stage)
            .iter()
            .flat_map(|unit| unit.ownership.source_paths.iter().cloned())
            .collect::<Vec<_>>();
        assert_eq!(
            owned,
            plan.unit(&unit_id(&plan, "services/big", "go"))
                .unwrap()
                .source_paths
        );
    }
    // Unit identity and input fingerprints belong to discovery and are
    // unchanged; a plan consumer keys saved results on them plus the
    // execution unit identity, not on the budget.
    let ids = |split_plan: &AnalysisSplitPlan| {
        split_plan
            .execution_units
            .iter()
            .map(|unit| unit.unit_id.clone())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(ids(&default_split), ids(&file_split));
    Ok(())
}

#[test]
fn out_of_unit_references_are_retained_in_loader_and_reference_scope() -> Result<()> {
    let checkout = Checkout::new()?;
    let (config, budget) = budget(|_| {});
    let plan = checkout.discover(&config)?;
    let (split_plan, _) = split(
        &checkout,
        &plan,
        &budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    let shared = unit_id(&plan, "services/shared", "go");
    let api_semantic = only(
        &split_plan,
        &plan,
        "services/api",
        "go",
        AnalysisStage::Semantic,
    );
    assert_eq!(api_semantic.loader.kind, AnalysisLoaderKind::Module);
    assert_eq!(
        api_semantic.loader.reference_depth,
        AnalysisReferenceDepth::Bodies
    );
    assert!(api_semantic.loader.reference_unit_ids.contains(&shared));
    assert!(
        api_semantic
            .loader
            .paths
            .contains(&"services/shared/shared.go".to_owned())
    );
    assert!(
        api_semantic.loader.reference_paths.is_empty(),
        "module loader holds everything it reads"
    );
    assert_eq!(
        api_semantic.estimate.dependency_closure_units,
        api_semantic.loader.reference_unit_ids.len() as u64
    );
    assert!(
        !api_semantic
            .loader
            .paths
            .contains(&"services/unrelated/unrelated.go".to_owned())
    );

    let api_syntax = only(
        &split_plan,
        &plan,
        "services/api",
        "go",
        AnalysisStage::Syntax,
    );
    assert_eq!(api_syntax.loader.kind, AnalysisLoaderKind::Files);
    assert_eq!(api_syntax.loader.paths, api_syntax.ownership.source_paths);
    assert!(
        api_syntax
            .loader
            .reference_paths
            .contains(&"services/shared/shared.go".to_owned())
    );
    assert_eq!(
        api_syntax.loader.reference_depth,
        AnalysisReferenceDepth::PathsOnly
    );
    assert!(api_syntax.loader.input_split);

    let web_semantic = only(
        &split_plan,
        &plan,
        "frontend/apps/web",
        "web",
        AnalysisStage::Semantic,
    );
    assert!(
        web_semantic
            .loader
            .paths
            .contains(&"frontend/packages/shared-web/src/index.ts".to_owned())
    );
    assert!(web_semantic.loader.reference_unit_ids.contains(&unit_id(
        &plan,
        "frontend/packages/shared-web",
        "web"
    )));
    let static_context = static_context_paths(
        &plan,
        plan.unit(&unit_id(&plan, "services/api", "go")).unwrap(),
    );
    assert_eq!(static_context, api_semantic.loader.paths);
    Ok(())
}

#[test]
fn large_single_package_is_expressed_as_a_staged_split() -> Result<()> {
    let checkout = Checkout::new()?;
    let (config, budget) = budget(|_| {});
    let plan = checkout.discover(&config)?;

    // The shipped Go worker loads the whole module for typed and semantic
    // work; the plan says so and marks the package as over budget instead
    // of pretending the output split reduces loader input.
    let (module_split, _) = split(
        &checkout,
        &plan,
        &budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    for stage in [AnalysisStage::Typed, AnalysisStage::Semantic] {
        let unit = only(&module_split, &plan, "services/big", "go", stage);
        assert_eq!(unit.split_kind, AnalysisSplitKind::Whole);
        assert_eq!(unit.loader.kind, AnalysisLoaderKind::Module);
        assert!(unit.estimate.over_budget);
        assert!(
            unit.split_reasons
                .contains(&AnalysisSplitReason::AdapterBoundaryUnsplittable)
        );
        assert!(!unit.loader.input_split);
    }
    let syntax = units(
        &module_split,
        &plan,
        "services/big",
        "go",
        AnalysisStage::Syntax,
    );
    assert_eq!(
        syntax.len(),
        2,
        "8 x 2 MiB owned bytes split at the 8 MiB unit budget"
    );
    assert!(syntax.iter().all(|unit| {
        unit.split_reasons
            .contains(&AnalysisSplitReason::SourceByteBudget)
    }));
    assert!(
        module_split
            .limitations
            .contains(&AnalysisSplitLimitation::WholeContextLoaderRetained)
    );

    // A package-capable Go worker receives a declaration stage for the whole
    // package and body batches that reference those declarations.
    let (staged_split, _) = split(
        &checkout,
        &plan,
        &budget,
        vec![
            AnalysisAdapterBoundary::go_package_loader(),
            AnalysisAdapterBoundary::web_project_loader(),
        ],
    )?;
    let typed = only(
        &staged_split,
        &plan,
        "services/big",
        "go",
        AnalysisStage::Typed,
    );
    assert_eq!(typed.loader.kind, AnalysisLoaderKind::Package);
    assert_eq!(
        typed.loader.reference_depth,
        AnalysisReferenceDepth::Declarations
    );
    assert_eq!(
        typed.ownership.package_roots,
        vec!["services/big".to_owned()]
    );
    assert!(
        typed.estimate.over_budget,
        "one package cannot be type-checked in pieces"
    );
    assert!(
        typed
            .split_reasons
            .contains(&AnalysisSplitReason::SourceByteBudget)
    );
    let bodies = units(
        &staged_split,
        &plan,
        "services/big",
        "go",
        AnalysisStage::Semantic,
    );
    assert_eq!(bodies.len(), 2);
    for batch in &bodies {
        assert_eq!(batch.split_kind, AnalysisSplitKind::StagedBodies);
        assert!(
            batch
                .split_reasons
                .contains(&AnalysisSplitReason::StagedAfterDeclarations)
        );
        assert_eq!(batch.loader.kind, AnalysisLoaderKind::Package);
        assert_eq!(batch.loader.paths, batch.ownership.source_paths);
        assert_eq!(
            batch.loader.reference_depth,
            AnalysisReferenceDepth::Declarations
        );
        assert!(batch.loader.input_split);
        assert_eq!(batch.prerequisite_ids, vec![typed.id.clone()]);
        assert!(!batch.estimate.over_budget);
        assert_eq!(batch.estimate.owned_source_bytes, 4 * 2_097_152);
        let overlap = batch
            .loader
            .paths
            .iter()
            .filter(|path| batch.loader.reference_paths.contains(path))
            .count();
        assert_eq!(overlap, 0, "bodies and declaration references are disjoint");
    }
    let mut owned = bodies
        .iter()
        .flat_map(|batch| batch.ownership.source_paths.iter().cloned())
        .collect::<Vec<_>>();
    owned.sort();
    assert_eq!(
        owned,
        plan.unit(&unit_id(&plan, "services/big", "go"))
            .unwrap()
            .source_paths
    );
    // The multi-package api module becomes one typed execution unit that
    // loads both of its packages; small packages share a loader.
    let api_typed = only(
        &staged_split,
        &plan,
        "services/api",
        "go",
        AnalysisStage::Typed,
    );
    assert_eq!(
        api_typed.loader.package_roots,
        vec![
            "services/api".to_owned(),
            "services/api/handlers".to_owned()
        ]
    );
    assert!(
        api_typed.loader.input_split,
        "shared module sources are declarations, not loaded bodies"
    );
    Ok(())
}

#[test]
fn cycle_group_is_kept_in_one_analysis_context() -> Result<()> {
    let checkout = Checkout::new()?;
    let (config, budget) = budget(|_| {});
    let plan = checkout.discover(&config)?;
    let (split_plan, _) = split(
        &checkout,
        &plan,
        &budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    let a = only(
        &split_plan,
        &plan,
        "services/cycle-a",
        "go",
        AnalysisStage::Semantic,
    );
    let b = only(
        &split_plan,
        &plan,
        "services/cycle-b",
        "go",
        AnalysisStage::Semantic,
    );
    assert!(a.ownership.cyclic_group && b.ownership.cyclic_group);
    assert_eq!(a.ownership.context_group_id, b.ownership.context_group_id);
    assert_eq!(
        a.ownership.context_group_unit_ids,
        b.ownership.context_group_unit_ids
    );
    assert!(
        a.split_reasons
            .contains(&AnalysisSplitReason::CycleGroupRetained)
    );
    for unit in [a, b] {
        assert!(
            unit.loader
                .paths
                .contains(&"services/cycle-a/a.go".to_owned())
        );
        assert!(
            unit.loader
                .paths
                .contains(&"services/cycle-b/b.go".to_owned())
        );
    }
    assert!(a.loader.reference_unit_ids.contains(&b.unit_id));
    assert!(b.loader.reference_unit_ids.contains(&a.unit_id));
    // Syntax only needs paths; the cycle does not force a shared parser context.
    let a_syntax = only(
        &split_plan,
        &plan,
        "services/cycle-a",
        "go",
        AnalysisStage::Syntax,
    );
    assert!(
        !a_syntax
            .split_reasons
            .contains(&AnalysisSplitReason::CycleGroupRetained)
    );
    // Workspace membership is topology, not an input cycle.
    for root in [
        "services/api",
        "services/big",
        "services/shared",
        "services/unrelated",
    ] {
        let unit = only(&split_plan, &plan, root, "go", AnalysisStage::Semantic);
        assert!(!unit.ownership.cyclic_group, "{root} is not cyclic");
        assert!(
            !unit
                .split_reasons
                .contains(&AnalysisSplitReason::CycleGroupRetained)
        );
    }
    let web = only(
        &split_plan,
        &plan,
        "frontend/apps/web",
        "web",
        AnalysisStage::Semantic,
    );
    assert!(!web.ownership.cyclic_group);
    Ok(())
}

#[test]
fn resplit_supersedes_only_the_refined_unit_and_keeps_other_saved_results() -> Result<()> {
    let checkout = Checkout::new()?;
    let (config, budget) = budget(|_| {});
    let plan = checkout.discover(&config)?;
    let (current, input) = split(
        &checkout,
        &plan,
        &budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    let big_syntax = units(&current, &plan, "services/big", "go", AnalysisStage::Syntax);
    let target = big_syntax[0].clone();
    assert_eq!(target.ownership.source_paths.len(), 4);
    let big_typed = only(&current, &plan, "services/big", "go", AnalysisStage::Typed)
        .id
        .clone();

    let resplit = resplit_execution_unit(
        &plan,
        &current,
        &input,
        &target.id,
        AnalysisResplitTrigger::WorkerTimeout,
    )?;
    assert_eq!(resplit.outcome, AnalysisResplitOutcome::Split);
    assert_eq!(resplit.plan_id, plan.plan_id);
    assert_eq!(resplit.previous_split_plan_id, current.split_plan_id);
    assert_ne!(resplit.split_plan_id, current.split_plan_id);
    assert_eq!(
        resplit.superseded_execution_unit_ids,
        vec![target.id.clone()]
    );
    assert_eq!(resplit.replacement_execution_unit_ids.len(), 2);
    assert_eq!(
        resplit.retained_execution_unit_ids.len(),
        current.execution_units.len() - 1
    );
    assert!(resplit.retained_execution_unit_ids.contains(&big_typed));
    let disposition = |id: &str| {
        resplit
            .saved_results
            .iter()
            .find(|entry| entry.execution_unit_id == id)
            .map(|entry| entry.disposition)
    };
    assert_eq!(
        disposition(&target.id),
        Some(AnalysisSavedResultDisposition::Superseded)
    );
    assert_eq!(
        disposition(&big_typed),
        Some(AnalysisSavedResultDisposition::Retained)
    );
    for id in &resplit.replacement_execution_unit_ids {
        assert_eq!(
            disposition(id),
            Some(AnalysisSavedResultDisposition::Replacement)
        );
        let replacement = resplit.plan.execution_unit(id).unwrap();
        assert_eq!(replacement.ownership.source_paths.len(), 2);
        assert!(
            replacement
                .split_reasons
                .contains(&AnalysisSplitReason::Refined)
        );
        assert!(
            target
                .ownership
                .source_paths
                .iter()
                .any(|path| replacement.ownership.source_paths.contains(path))
        );
    }
    // The later stage now waits for the replacements; its own identity and
    // saved result are untouched because chunking does not enter its key.
    let typed_after = resplit.plan.execution_unit(&big_typed).unwrap();
    assert_eq!(typed_after.prerequisite_ids.len(), 3);
    assert!(
        resplit
            .replacement_execution_unit_ids
            .iter()
            .all(|id| typed_after.prerequisite_ids.contains(id))
    );
    assert_eq!(resplit.plan.refinements.len(), 1);
    assert_eq!(
        resplit.plan.refinements[0].trigger,
        AnalysisResplitTrigger::WorkerTimeout
    );
    // Re-planning from the recorded refinement history reproduces the plan.
    let replayed = plan_analysis_split(
        &plan,
        &input
            .clone()
            .with_refinements(resplit.plan.refinements.clone()),
    )?;
    assert_eq!(replayed.split_plan_id, resplit.split_plan_id);
    assert_eq!(
        serde_json::to_value(&replayed)?,
        serde_json::to_value(&resplit.plan)?
    );

    // A chained re-split of one replacement keeps every other result.
    let chained = resplit_execution_unit(
        &plan,
        &resplit.plan,
        &input,
        &resplit.replacement_execution_unit_ids[0],
        AnalysisResplitTrigger::WorkerMemory,
    )?;
    assert_eq!(chained.outcome, AnalysisResplitOutcome::Split);
    assert_eq!(
        chained.superseded_execution_unit_ids,
        vec![resplit.replacement_execution_unit_ids[0].clone()]
    );
    assert!(
        chained
            .retained_execution_unit_ids
            .contains(&resplit.replacement_execution_unit_ids[1])
    );

    // Adapter boundaries and single files cannot be split further; the plan
    // and its identity are unchanged and every saved result is retained.
    let boundary = resplit_execution_unit(
        &plan,
        &current,
        &input,
        &big_typed,
        AnalysisResplitTrigger::WorkerMemory,
    )?;
    assert_eq!(boundary.outcome, AnalysisResplitOutcome::Unsplittable);
    assert_eq!(
        boundary.unsplittable_reason,
        Some(AnalysisUnsplittableReason::AdapterBoundary)
    );
    assert_eq!(boundary.split_plan_id, current.split_plan_id);
    assert_eq!(
        serde_json::to_value(&boundary.plan)?,
        serde_json::to_value(&current)?
    );
    assert_eq!(
        boundary.retained_execution_unit_ids.len(),
        current.execution_units.len()
    );
    let single = only(
        &current,
        &plan,
        "services/cycle-a",
        "go",
        AnalysisStage::Syntax,
    )
    .id
    .clone();
    let granule = resplit_execution_unit(
        &plan,
        &current,
        &input,
        &single,
        AnalysisResplitTrigger::EstimateExceeded,
    )?;
    assert_eq!(
        granule.unsplittable_reason,
        Some(AnalysisUnsplittableReason::SingleGranule)
    );
    assert!(
        resplit_execution_unit(
            &plan,
            &current,
            &input,
            "analysis-execution-unit:missing",
            AnalysisResplitTrigger::OutputLimit
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn loader_scope_and_ownership_scope_are_distinguishable() -> Result<()> {
    let checkout = Checkout::new()?;
    let (config, _) = budget(|_| {});
    let (_, file_budget) = budget(|config| config.scan.max_unit_source_files = 2);
    let plan = checkout.discover(&config)?;
    let (split_plan, _) = split(
        &checkout,
        &plan,
        &file_budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    let web_semantic = units(
        &split_plan,
        &plan,
        "frontend/apps/web",
        "web",
        AnalysisStage::Semantic,
    );
    assert_eq!(web_semantic.len(), 2);
    for unit in &web_semantic {
        // Output-only split: the worker builds the whole project program.
        assert_eq!(unit.split_kind, AnalysisSplitKind::OutputBatch);
        assert_eq!(unit.loader.kind, AnalysisLoaderKind::Project);
        assert!(!unit.loader.input_split);
        assert!(unit.loader.paths.len() > unit.ownership.source_paths.len());
        assert!(
            unit.ownership
                .source_paths
                .iter()
                .all(|path| unit.loader.paths.contains(path))
        );
        assert_eq!(unit.estimate.loader_source_bytes, 1000);
        assert!(unit.estimate.owned_source_bytes < unit.estimate.loader_source_bytes);
        let binding = unit.binding(&split_plan.split_plan_id);
        assert_eq!(
            binding.contract_version,
            ANALYSIS_SPLIT_PLAN_CONTRACT_VERSION
        );
        assert_eq!(binding.execution_unit_id, unit.id);
        assert_eq!(binding.loader.paths, unit.loader.paths);
        assert!(!binding.loader.input_split);
    }
    let web_syntax = units(
        &split_plan,
        &plan,
        "frontend/apps/web",
        "web",
        AnalysisStage::Syntax,
    );
    for unit in &web_syntax {
        // Real input split: the parser reads only the owned files.
        assert_eq!(unit.split_kind, AnalysisSplitKind::InputBatch);
        assert_eq!(unit.loader.kind, AnalysisLoaderKind::Files);
        assert!(unit.loader.input_split);
        assert_eq!(unit.loader.paths, unit.ownership.source_paths);
        assert_eq!(
            unit.estimate.loader_source_bytes,
            unit.estimate.owned_source_bytes
        );
    }
    Ok(())
}

#[test]
fn parallelism_is_decided_before_execution_and_respects_prerequisites() -> Result<()> {
    let checkout = Checkout::new()?;
    let (config, default_budget) = budget(|_| {});
    let plan = checkout.discover(&config)?;
    let (split_plan, _) = split(
        &checkout,
        &plan,
        &default_budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    let parallelism = &split_plan.parallelism;
    assert_eq!(parallelism.max_concurrent_units, 2);
    assert_eq!(parallelism.effective_concurrency, 2);
    assert_eq!(
        parallelism.admitted_memory_bytes,
        2 * default_budget.max_worker_memory_bytes
    );
    let mut wave_of = BTreeMap::new();
    let mut scheduled = BTreeSet::new();
    for wave in &parallelism.waves {
        assert!(!wave.execution_unit_ids.is_empty());
        assert!(wave.execution_unit_ids.len() <= 2);
        for id in &wave.execution_unit_ids {
            wave_of.insert(id.clone(), wave.index);
            assert!(scheduled.insert(id.clone()), "{id} is admitted once");
        }
    }
    assert_eq!(scheduled.len(), split_plan.execution_units.len());
    for unit in &split_plan.execution_units {
        for prerequisite in &unit.prerequisite_ids {
            assert!(
                wave_of[prerequisite] < wave_of[&unit.id],
                "{} waits for its earlier stage",
                unit.id
            );
        }
    }
    let (_, serial) = budget(|config| config.scan.max_concurrent_units = 1);
    let (serial_split, _) = split(
        &checkout,
        &plan,
        &serial,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    assert_eq!(serial_split.parallelism.effective_concurrency, 1);
    assert!(
        serial_split
            .parallelism
            .waves
            .iter()
            .all(|wave| wave.execution_unit_ids.len() == 1)
    );
    Ok(())
}

#[test]
fn measured_sizes_match_fixture_bytes_and_drive_byte_splits() -> Result<()> {
    let checkout = Checkout::new()?;
    let (config, _) = budget(|_| {});
    let plan = checkout.discover(&config)?;
    let measured = measure_source_sizes(&checkout.root, &plan)?;
    for (path, size) in &measured {
        assert_eq!(*size, fs::metadata(checkout.root.join(path))?.len());
    }
    assert!(measured.contains_key("services/big/part0.go"));
    let (_, byte_budget) = budget(|config| {
        config.scan.max_unit_source_bytes = 150;
        config.scan.max_context_source_bytes = 150;
    });
    let input = AnalysisSplitInput::new(byte_budget, AnalysisAdapterBoundary::current_defaults())
        .with_sizes(measured);
    let split_plan = plan_analysis_split(&plan, &input)?;
    let big_syntax = units(
        &split_plan,
        &plan,
        "services/big",
        "go",
        AnalysisStage::Syntax,
    );
    assert!(big_syntax.len() > 1);
    assert!(big_syntax.iter().all(|unit| {
        unit.split_reasons
            .contains(&AnalysisSplitReason::SourceByteBudget)
    }));
    assert!(
        !split_plan
            .limitations
            .contains(&AnalysisSplitLimitation::SourceSizesIncomplete)
    );
    let partial = AnalysisSplitInput::new(
        AnalysisSplitBudget::from_config(&config),
        AnalysisAdapterBoundary::current_defaults(),
    );
    assert!(
        plan_analysis_split(&plan, &partial)?
            .limitations
            .contains(&AnalysisSplitLimitation::SourceSizesIncomplete)
    );
    Ok(())
}

#[test]
fn split_plan_and_resplit_plan_satisfy_the_closed_schema() -> Result<()> {
    let checkout = Checkout::new()?;
    let schema: Value = serde_json::from_str(SPLIT_PLAN_SCHEMA)?;
    let validator = jsonschema::validator_for(&schema)?;
    for (name, (plan, split_plan)) in scenarios(&checkout)? {
        let value = serde_json::to_value(&split_plan)?;
        let errors = validator
            .iter_errors(&value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        let round_trip: AnalysisSplitPlan = serde_json::from_value(value)?;
        assert_eq!(round_trip, split_plan);
        let _ = plan;
    }
    let (config, budget) = budget(|_| {});
    let plan = checkout.discover(&config)?;
    let (current, input) = split(
        &checkout,
        &plan,
        &budget,
        AnalysisAdapterBoundary::current_defaults(),
    )?;
    let target = units(&current, &plan, "services/big", "go", AnalysisStage::Syntax)[0]
        .id
        .clone();
    let resplit = resplit_execution_unit(
        &plan,
        &current,
        &input,
        &target,
        AnalysisResplitTrigger::WorkerTimeout,
    )?;
    let value = serde_json::to_value(&resplit.plan)?;
    assert!(validator.is_valid(&value));

    // The re-split result and the worker-facing `split` binding are closed
    // definitions of the same schema so #463 can validate a request's
    // `split` object and a re-split outcome without the core.
    let definition = |name: &str| -> Result<jsonschema::Validator> {
        // Embed the published document as its own resource so `#` references
        // inside it (the re-split `plan`) keep pointing at the split plan.
        let wrapper = json!({
            "$schema": schema["$schema"],
            "$ref": format!("{}#/$defs/{name}", schema["$id"].as_str().context("schema $id")?),
            "$defs": {"document": schema},
        });
        Ok(jsonschema::validator_for(&wrapper)?)
    };
    let resplit_validator = definition("resplitPlan")?;
    let resplit_value = serde_json::to_value(&resplit)?;
    let errors = resplit_validator
        .iter_errors(&resplit_value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "resplit plan: {errors:?}");
    let binding_validator = definition("splitBinding")?;
    for execution_unit in &current.execution_units {
        let binding = serde_json::to_value(execution_unit.binding(&current.split_plan_id))?;
        let errors = binding_validator
            .iter_errors(&binding)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "split binding: {errors:?}");
        assert!(
            binding.get("estimate").is_none() && binding.get("ownership").is_none(),
            "the worker binding carries the loader target only"
        );
    }
    let mut widened =
        serde_json::to_value(current.execution_units[0].binding(&current.split_plan_id))?;
    widened["loader"]["estimate"] = json!({});
    assert!(
        !binding_validator.is_valid(&widened),
        "the binding definition is closed"
    );
    let mut broken = serde_json::to_value(&resplit)?;
    broken["outcome"] = json!("partial");
    assert!(
        !resplit_validator.is_valid(&broken),
        "the re-split definition is closed"
    );
    Ok(())
}
