//! Progress observed during a #480 re-split keeps every unit of the scan
//! (issue #553).
//!
//! The fake worker is selected through `DEPGRAPH_WEB_WORKER`, so this file
//! owns its process environment.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::OnceLock};

use anyhow::Result;
use depgraph_core::{
    ScanCacheMode,
    analysis_execution::{AnalysisProgressObserver, observe_analysis_progress},
    config::Config,
    run_scan_with_cache_mode,
};
use depgraph_store::Store;

const MAX_PROTOCOL_BYTES: usize = 1024 * 1024;

static WORKER: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();

/// A Web worker that negotiates source batches and overruns the protocol
/// limit for any batch of more than one source file, so a two-file batch is
/// re-split into single-file replacements at both the syntax and the
/// semantic stage. The output of a single-file batch lacks a logical profile,
/// so it fails ingestion; that is enough here, where only unit progress is
/// observed.
const WEB_WORKER: &str = r#"#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
if (args.includes('--version')) {
  console.log('depgraph-web-worker 0.1.0 (protocol 1.0; capabilities analysis-source-batch-v1)');
  process.exit(0);
}
const arg = key => args[args.indexOf(key) + 1];
const request = JSON.parse(fs.readFileSync(arg('--analysis-unit'), 'utf8'));
const paths = request.source_paths;
const common = {protocol_version:'1.0',scan_id:arg('--scan-id'),adapter:'web',adapter_version:'0.1.0'};
const coverage = {profiles:1,files_discovered:paths.length,files_analyzed:paths.length,files_skipped:0,dependency_sites:0,resolved:0,candidates:0,external:0,unresolved:0,unsupported_syntax:0,project_code_executed:false,completeness:['syntax-complete'],reasons:[]};
const profile = {id:'web:'+request.unit_id,language:'web',features:[],environment:{},properties:{analysis_unit_contract:request.contract_version,analysis_unit_id:request.unit_id,analysis_unit_root:request.unit_root,analysis_stage:request.stage,analysis_chunk_id:request.chunk_id,analysis_context_fingerprint:request.context_fingerprint,analysis_chunk_index:String(request.chunk_index),analysis_chunk_count:String(request.chunk_count),typescript_analysis_mode:'semantic-definition-graph',typescript_project_model_status:'ready',typescript_typechecker_status:'definition-graph-emitted',typescript_definition_graph_status:'ready',typescript_semantic_graph_emission:'definition-graph-v1',typescript_semantic_node_count:'0',typescript_semantic_relation_count:'0',typescript_semantic_issue_count:'0',typescript_release_gate:'release-gate-pending'}};
let seq = 0;
const emit = event => fs.writeSync(1, JSON.stringify({...common, ...event, seq: ++seq}) + '\n');
emit({event:'scan_started',root:arg('--root'),project_code_executed:false,safe_mode:true});
emit({event:'profile_declared',profile});
if (paths.length > 1) {
  fs.writeSync(1, Buffer.alloc(2 * 1024 * 1024, 32));
  process.exit(0);
}
for (const path of paths) emit({event:'file_completed',path,discovered_sites:0,emitted_sites:0,skipped_sites:0,skipped:false});
emit({event:'profile_completed',profile_id:profile.id,coverage});
emit({event:'scan_completed',coverage});
"#;

fn install_worker() {
    let (_, path) = WORKER.get_or_init(|| {
        let directory = tempfile::tempdir().expect("worker directory");
        let path = directory.path().join("depgraph-web-worker");
        fs::write(&path, WEB_WORKER).expect("write worker");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod worker");
        (directory, path)
    });
    // SAFETY: every test in this binary installs the same value before it
    // starts a scan, and nothing else reads or writes this variable.
    unsafe { std::env::set_var("DEPGRAPH_WEB_WORKER", path) };
}

fn unit_order(units: &[depgraph_core::analysis_execution::AnalysisUnitProgress]) -> Vec<String> {
    units
        .iter()
        .map(|unit| {
            format!(
                "{} {} {}",
                unit.unit_id,
                unit.status,
                unit.loader
                    .get("analysis_resplit")
                    .map(String::as_str)
                    .unwrap_or("-")
            )
        })
        .collect()
}

#[tokio::test]
async fn resplit_progress_keeps_every_unit_in_the_order_of_the_result() -> Result<()> {
    install_worker();
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("package.json"),
        r#"{"name":"resplit-progress","version":"0.1.0"}"#,
    )?;
    for name in ["a", "b", "c"] {
        fs::write(
            root.path().join(format!("{name}.js")),
            format!("export const {name} = 1;\n"),
        )?;
    }
    let store_dir = tempfile::tempdir()?;
    let mut store = Store::open(store_dir.path().join("graph.db"))?;
    let mut config = Config::load(root.path())?;
    config.scan.max_unit_source_files = 2;
    config.scan.max_concurrent_units = 1;
    config.scan.max_protocol_bytes = MAX_PROTOCOL_BYTES;
    config.scan.max_protocol_line_bytes = MAX_PROTOCOL_BYTES;
    let observer = AnalysisProgressObserver::default();

    let outcome = observe_analysis_progress(
        observer.clone(),
        run_scan_with_cache_mode(
            &mut store,
            root.path().to_path_buf(),
            &config,
            false,
            ScanCacheMode::Disabled,
        ),
    )
    .await?;

    let analysis = outcome.analysis.expect("analysis progress");
    let result = unit_order(&analysis.units);
    // Two re-splits, so the second one starts from a base that already holds
    // the first one's replacements.
    assert_eq!(
        result
            .iter()
            .filter(|unit| unit.ends_with("superseded"))
            .count(),
        2,
        "the fixture must re-split both stages of a batch: {analysis:#?} {:#?}",
        outcome.diagnostics
    );
    assert!(
        result.iter().any(|unit| unit.ends_with("replacement")),
        "{analysis:#?}"
    );
    assert!(
        result.iter().any(|unit| unit.ends_with(" -")),
        "{analysis:#?}"
    );
    assert_eq!(unit_order(&observer.snapshot().units), result);
    Ok(())
}
