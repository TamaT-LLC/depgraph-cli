//! Evidence runner for ranged health collection (#467).
//!
//! Generates the public over-limit fixture (plan fixture B) or reads an
//! existing store, then records in one JSON report:
//!
//! - the whole-snapshot control under the unchanged single budget
//!   (`resource_exhausted` is the "before" outcome),
//! - the unbounded whole-snapshot control (required work, findings),
//! - the ranged service path with the production limits (ranges, per-range
//!   work, checkpoints, peak RSS), and
//! - whether both paths produced identical unused findings.
//!
//! No repository content, path, or identifier of a private store is written:
//! the report of `--store` runs contains counts, work, timings, and digests.
//!
//! ```text
//! cargo run -p depgraph-core --example health_range_e2e -- \
//!     --shape over-limit --work-dir target/health-range-e2e --report report.json
//! cargo run -p depgraph-core --example health_range_e2e -- \
//!     --store /path/to/depgraph.sqlite --root /path/to/repo --report report.json
//! ```

#[path = "../tests/support/health_range_fixture.rs"]
mod fixture;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use depgraph_core::{
    CancellationToken, FindingKind, HealthFinding,
    health::{HealthAnalysisError, analyze_unused_measured, ranged::peak_rss_kib},
    service::{
        DepgraphCapabilitySet, DepgraphService, DepgraphServiceConfig, DepgraphServiceLimits,
        HealthFindingsRequest, HealthSummaryRequest, MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        MAX_HEALTH_FINDINGS, SnapshotLocator, health_range_limits,
    },
};
use depgraph_store::Store;
use serde_json::{Value, json};

use fixture::HealthRangeFixtureShape;

struct Options {
    shape: Option<String>,
    store: Option<PathBuf>,
    root: Option<PathBuf>,
    work_dir: Option<PathBuf>,
    report: Option<PathBuf>,
    /// Generate the fixture and stop, so a second process can measure the
    /// ranged path with a peak RSS that excludes fixture generation.
    generate_only: bool,
}

fn parse(args: impl Iterator<Item = String>) -> Result<Options> {
    let mut options = Options {
        shape: None,
        store: None,
        root: None,
        work_dir: None,
        report: None,
        generate_only: false,
    };
    let mut args = args.peekable();
    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .with_context(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--shape" => options.shape = Some(value()?),
            "--store" => options.store = Some(PathBuf::from(value()?)),
            "--root" => options.root = Some(PathBuf::from(value()?)),
            "--work-dir" => options.work_dir = Some(PathBuf::from(value()?)),
            "--report" => options.report = Some(PathBuf::from(value()?)),
            "--generate-only" => options.generate_only = true,
            other => bail!("unknown argument {other}"),
        }
    }
    if options.shape.is_some() && options.store.is_some() {
        bail!("--shape and --store are mutually exclusive");
    }
    if options.store.is_some() != options.root.is_some() {
        bail!("--store requires --root (the repository the snapshot was scanned from)");
    }
    if options.generate_only && options.store.is_some() {
        bail!("--generate-only applies to generated shapes only");
    }
    Ok(options)
}

fn shape_named(name: &str) -> Result<HealthRangeFixtureShape> {
    Ok(match name {
        "over-limit" => HealthRangeFixtureShape::over_limit(),
        "small" => HealthRangeFixtureShape::small(),
        "later-range-callers" => HealthRangeFixtureShape::small().with_caller_after_callee(true),
        other => bail!("unknown fixture shape {other}"),
    })
}

fn unused_only(findings: &[HealthFinding]) -> Vec<HealthFinding> {
    findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::UnusedFile | FindingKind::UnusedExport | FindingKind::UnusedType
            )
        })
        .cloned()
        .collect()
}

fn counts(findings: &[HealthFinding]) -> Value {
    let mut by_kind = BTreeMap::<&str, u64>::new();
    let mut by_confidence = BTreeMap::<&str, u64>::new();
    for finding in findings {
        *by_kind.entry(finding.kind.as_str()).or_insert(0) += 1;
        *by_confidence
            .entry(finding.confidence.as_str())
            .or_insert(0) += 1;
    }
    json!({
        "total": findings.len(),
        "by_kind": by_kind,
        "by_confidence": by_confidence,
    })
}

fn analysis_outcome(error: &HealthAnalysisError) -> &'static str {
    match error {
        HealthAnalysisError::Cancelled => "cancelled",
        HealthAnalysisError::ResourceExhausted => "resource_exhausted",
        HealthAnalysisError::Integrity => "integrity",
    }
}

fn service(root: &Path, store: &Path) -> Result<DepgraphService> {
    Ok(DepgraphService::new(DepgraphServiceConfig::new(
        root,
        store,
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )?))
}

fn run(options: &Options) -> Result<Value> {
    let started = Instant::now();
    let mut report = json!({
        "contract": "depgraph-health-range-e2e-report-v1",
        "limits": health_range_limits(),
        "whole_snapshot_work_limit": MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
    });

    // 1. Input: generate the public fixture or address an existing store.
    let (store_path, root) = if let Some(store) = &options.store {
        report["input"] = json!({"kind": "store", "public": false});
        (
            store.clone(),
            options.root.clone().context("--root is required")?,
        )
    } else {
        let name = options
            .shape
            .clone()
            .unwrap_or_else(|| "over-limit".to_owned());
        let shape = shape_named(&name)?;
        let work_dir = options
            .work_dir
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("depgraph-health-range-e2e"));
        let generate_started = Instant::now();
        let generated = fixture::generate(&work_dir, &shape)?;
        report["input"] = json!({
            "kind": "generated",
            "public": true,
            "shape": name,
            "packages": shape.packages,
            "files": shape.files,
            "symbols": shape.symbols,
            "profiles": shape.profiles,
            "cross_percent": shape.cross_percent,
            "caller_after_callee": shape.caller_after_callee,
            "events": generated.events,
            "edges": generated.edges,
            "sites": generated.sites,
            "generate_ms": generate_started.elapsed().as_millis() as u64,
            "store_bytes": std::fs::metadata(&generated.store_path)?.len(),
            "peak_rss_kib_after_generate": peak_rss_kib(),
        });
        if options.generate_only {
            report["input"]["store"] = json!(generated.store_path);
            report["input"]["root"] = json!(generated.root);
            report["elapsed_ms"] = json!(started.elapsed().as_millis() as u64);
            return Ok(report);
        }
        (generated.store_path, generated.root)
    };

    // 2. Ranged path first so its peak RSS is not inflated by the control.
    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let ranged_started = Instant::now();
    let mut request =
        service.start_snapshot_request_at_cancellable(&SnapshotLocator::Current, &cancellation)?;
    let findings = service.health_findings(
        &mut request,
        &HealthFindingsRequest::try_new(Vec::new(), Vec::new(), Vec::new(), MAX_HEALTH_FINDINGS)?,
        &cancellation,
    )?;
    let ranged_ms = ranged_started.elapsed().as_millis() as u64;
    let ranged_unused = unused_only(findings.findings());
    let resumed_started = Instant::now();
    let summary = service.health_summary(
        &mut request,
        &HealthSummaryRequest::try_new(None)?,
        &cancellation,
    )?;
    let resumed_ms = resumed_started.elapsed().as_millis() as u64;
    let snapshot_id = request.snapshot_id().as_str().to_owned();
    report["ranged"] = json!({
        "outcome": "completed",
        "elapsed_ms": ranged_ms,
        "partial_ranges": findings.partial(),
        "collection_digest": findings.collection_digest(),
        "findings": counts(findings.findings()),
        "unused_findings": counts(&ranged_unused),
        "execution": findings.diagnostics(),
        "resumed": {
            "elapsed_ms": resumed_ms,
            "collection_digest": summary.collection_digest(),
            "execution": summary.diagnostics(),
        },
    });
    drop(request);
    drop(service);

    // 3. Whole-snapshot control under the unchanged single budget.
    let store = Store::open_read_only(&store_path)?;
    let load_started = Instant::now();
    let snapshot = store.load_completed_snapshot(&snapshot_id)?;
    let load_ms = load_started.elapsed().as_millis() as u64;
    let bounded_started = Instant::now();
    let bounded = analyze_unused_measured(
        &snapshot,
        MAX_HEALTH_FINDINGS,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        || false,
    );
    let bounded_ms = bounded_started.elapsed().as_millis() as u64;
    let unbounded_started = Instant::now();
    let unbounded = analyze_unused_measured(&snapshot, MAX_HEALTH_FINDINGS, usize::MAX, || false);
    let unbounded_ms = unbounded_started.elapsed().as_millis() as u64;
    let snapshot_rows = json!({
        "nodes": snapshot.nodes.len(),
        "edges": snapshot.edges.len(),
        "sites": snapshot.sites.len(),
        "evidence": snapshot.evidence.len(),
        "profiles": snapshot.profiles.len(),
    });
    drop(snapshot);
    let (unbounded_findings, unbounded_work) = match unbounded {
        Ok((findings, work)) => (Some(findings), Some(work)),
        Err(_) => (None, None),
    };
    report["whole_snapshot"] = json!({
        "load_ms": load_ms,
        "rows": snapshot_rows,
        "bounded": match &bounded {
            Ok((findings, work)) => json!({
                "outcome": "completed", "work_used": work, "findings": findings.len(),
                "elapsed_ms": bounded_ms,
            }),
            Err(error) => json!({
                "outcome": analysis_outcome(error),
                "work_limit": MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
                "elapsed_ms": bounded_ms,
            }),
        },
        "unbounded": json!({
            "outcome": unbounded_findings.as_ref().map_or("failed", |_| "completed"),
            "work_used": unbounded_work,
            "elapsed_ms": unbounded_ms,
            "unused_findings": unbounded_findings.as_deref().map(counts),
        }),
        "peak_rss_kib_after_control": peak_rss_kib(),
    });

    // 4. Equality of the two collections.
    let equal = unbounded_findings
        .as_ref()
        .is_some_and(|control| *control == ranged_unused);
    let diagnostics = findings.diagnostics();
    report["comparison"] = json!({
        "unused_findings_equal": equal,
        "whole_snapshot_exceeds_single_budget": matches!(
            bounded,
            Err(HealthAnalysisError::ResourceExhausted)
        ),
        "ranges_max_within_limit": diagnostics.work.ranges_max <= diagnostics.work.range_limit,
        "every_range_completed": diagnostics.ranges.completed == diagnostics.ranges.total
            && diagnostics.ranges.failed == 0
            && diagnostics.ranges.interrupted == 0,
        "checkpoints_reused_on_resume": summary.diagnostics().ranges.reused
            == summary.diagnostics().ranges.total,
    });
    report["elapsed_ms"] = json!(started.elapsed().as_millis() as u64);
    Ok(report)
}

fn main() -> ExitCode {
    let options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("health_range_e2e: {error:#}");
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(report) => {
            let rendered = serde_json::to_string_pretty(&report).expect("report is JSON");
            if let Some(path) = &options.report {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(error) = std::fs::write(path, format!("{rendered}\n")) {
                    eprintln!(
                        "health_range_e2e: failed to write {}: {error}",
                        path.display()
                    );
                    return ExitCode::from(1);
                }
            }
            println!("{rendered}");
            if options.generate_only {
                return ExitCode::SUCCESS;
            }
            let comparison = &report["comparison"];
            let passed = comparison["unused_findings_equal"] == json!(true)
                && comparison["ranges_max_within_limit"] == json!(true)
                && comparison["every_range_completed"] == json!(true);
            if passed {
                ExitCode::SUCCESS
            } else {
                eprintln!("health_range_e2e: ranged and whole-snapshot results diverge");
                ExitCode::from(1)
            }
        }
        Err(error) => {
            eprintln!("health_range_e2e: {error:#}");
            ExitCode::from(1)
        }
    }
}
