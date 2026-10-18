//! A Rust worker that exceeds its memory budget is retried once in
//! syntax-only mode (issue #538).
//!
//! The fake worker is selected through `DEPGRAPH_RUST_WORKER`, so this file
//! owns its process environment: every test installs the same worker through
//! one `Once` before it starts a scan, and the worker's behaviour is chosen by
//! a marker file inside each scan root.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::Result;
use depgraph_core::{
    ScanCacheMode,
    analysis_execution::{AnalysisProgressObserver, observe_analysis_progress},
    config::Config,
    run_scan_with_cache_mode,
};
use depgraph_store::Store;

const MEMORY_BUDGET_BYTES: u64 = 128 * 1024 * 1024;
const FAIL_SYNTAX_ONLY_MARKER: &str = "fail-syntax-only";
const FULL_MODE_PREFIX_MARKER: &str = "emit-full-mode-prefix";
const FULL_MODE_PROFILE_ID: &str = "rust:full-mode-prefix";
const INVOCATION_LOG: &str = "DEPGRAPH_TEST_RUST_INVOCATION_LOG";

static WORKER: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();

/// A Web worker that completes at once, so a mixed scan has a finished
/// non-Rust unit while the Rust unit is retried.
const WEB_WORKER: &str = r#"const args = process.argv.slice(2);
const root = args[args.indexOf("--root") + 1];
const scan = args[args.indexOf("--scan-id") + 1];
const common = {protocol_version:"1.0",scan_id:scan,adapter:"web",adapter_version:"0.1.0"};
const coverage = {profiles:1,files_discovered:0,files_analyzed:0,files_skipped:0,dependency_sites:0,resolved:0,candidates:0,external:0,unresolved:0,unsupported_syntax:0,project_code_executed:false,completeness:["syntax-complete"],reasons:[]};
const events = [
  {event:"scan_started",...common,seq:1,root,project_code_executed:false,safe_mode:true},
  {event:"profile_declared",...common,seq:2,profile:{id:"web:test",language:"web",features:[],environment:{},properties:{typescript_analysis_mode:"semantic-definition-graph",typescript_project_model_status:"ready",typescript_typechecker_status:"definition-graph-emitted",typescript_definition_graph_status:"ready",typescript_semantic_graph_emission:"definition-graph-v1",typescript_semantic_node_count:"0",typescript_semantic_relation_count:"0",typescript_semantic_issue_count:"0",typescript_release_gate:"release-gate-pending"}}},
  {event:"profile_completed",...common,seq:3,profile_id:"web:test",coverage},
  {event:"scan_completed",...common,seq:4,coverage}
];
for (const event of events) console.log(JSON.stringify(event));
"#;

fn rust_event(event: &str, seq: u64, payload: &str, extra_arguments: &str) -> String {
    format!(
        r#"printf '{{"event":"{event}","protocol_version":"1.0","scan_id":"%s","adapter":"rust","adapter_version":"0.1.0","seq":{seq}{payload}}}\n' "$scan"{extra_arguments}"#
    )
}

/// Full mode holds far more resident memory than the budget until the core
/// stops it, optionally after emitting a valid protocol prefix; syntax-only
/// mode emits a small valid graph unless the scan root asks it to exceed the
/// budget again.
fn worker_script(log: &Path) -> String {
    let coverage = r#"{"profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,"dependency_sites":0,"resolved":0,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete"],"reasons":["rust-hir-memory-budget"]}"#;
    let exceed_budget = "exec perl -e '$x = \"a\" x (512 * 1024 * 1024); sleep 30'";
    [
        "#!/bin/sh".to_owned(),
        "set -eu".to_owned(),
        format!("printf '%s\\n' \"$*\" >> {}", shell_quote(log)),
        r#"root=''
scan=''
mode='full'
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    --hir-mode) mode="$2"; shift 2 ;;
    *) shift ;;
  esac
done"#
            .to_owned(),
        format!(
            "if [ \"$mode\" != syntax-only ] && [ -e \"$root/{FULL_MODE_PREFIX_MARKER}\" ]; then\n{}\n{}\nfi",
            rust_event(
                "scan_started",
                1,
                r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
                r#" "$root""#,
            ),
            rust_event(
                "profile_declared",
                2,
                &format!(
                    r#", "profile":{{"id":"{FULL_MODE_PROFILE_ID}","language":"rust","features":[],"environment":{{}},"properties":{{"analysis":"full"}}}}"#
                ),
                "",
            ),
        ),
        format!(
            "if [ \"$mode\" != syntax-only ] || [ -e \"$root/{FAIL_SYNTAX_ONLY_MARKER}\" ]; then {exceed_budget}; fi"
        ),
        rust_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        rust_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"rust:test","language":"rust","features":[],"environment":{},"properties":{"analysis":"syntax","rust_hir_mode":"syntax-only"}}"#,
            "",
        ),
        rust_event(
            "file_completed",
            3,
            r#", "path":"Cargo.toml","discovered_sites":0,"emitted_sites":0,"skipped_sites":0,"skipped":false"#,
            "",
        ),
        rust_event(
            "profile_completed",
            4,
            &format!(r#", "profile_id":"rust:test","coverage":{coverage}"#),
            "",
        ),
        rust_event(
            "scan_completed",
            5,
            &format!(r#", "coverage":{coverage}"#),
            "",
        ),
    ]
    .join("\n")
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn install_worker() -> &'static Path {
    let (_, log) = WORKER.get_or_init(|| {
        let directory = tempfile::tempdir().unwrap();
        let worker = directory.path().join("memory-heavy-rust-worker.sh");
        let log = directory.path().join("invocations.log");
        fs::write(&worker, worker_script(&log)).unwrap();
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o755)).unwrap();
        let web_worker = directory.path().join("web-worker.mjs");
        fs::write(&web_worker, WEB_WORKER).unwrap();
        // SAFETY: every test in this binary reaches the environment only
        // through this `OnceLock`, which blocks concurrent initializers, and
        // no test has spawned a worker before the variable is installed.
        unsafe {
            std::env::set_var("DEPGRAPH_RUST_WORKER", &worker);
            std::env::set_var("DEPGRAPH_WEB_WORKER", &web_worker);
            std::env::set_var(INVOCATION_LOG, &log);
        }
        (directory, log)
    });
    log
}

fn rust_root(fail_syntax_only: bool) -> tempfile::TempDir {
    rust_root_with(fail_syntax_only, false)
}

fn rust_root_with(fail_syntax_only: bool, full_mode_prefix: bool) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname='memory-fallback-fixture'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(
        root.path().join(".depgraph.toml"),
        format!(
            "schema_version = 1\n[scan]\nworker_timeout_seconds = 30\nmax_worker_memory_bytes = {MEMORY_BUDGET_BYTES}\n"
        ),
    )
    .unwrap();
    if fail_syntax_only {
        fs::write(root.path().join(FAIL_SYNTAX_ONLY_MARKER), "").unwrap();
    }
    if full_mode_prefix {
        fs::write(root.path().join(FULL_MODE_PREFIX_MARKER), "").unwrap();
    }
    root
}

fn invocations_for(log: &Path, root: &Path) -> Vec<String> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains(root.to_string_lossy().as_ref()))
        .map(ToOwned::to_owned)
        .collect()
}

#[tokio::test]
async fn rust_memory_limit_retries_once_in_syntax_only_mode_and_completes() -> Result<()> {
    let log = install_worker();
    let root = rust_root(false);
    let store_dir = tempfile::tempdir()?;
    let mut store = Store::open(store_dir.path().join("graph.db"))?;
    let config = Config::load(root.path())?;

    let outcome = run_scan_with_cache_mode(
        &mut store,
        root.path().to_path_buf(),
        &config,
        false,
        ScanCacheMode::Disabled,
    )
    .await?;

    assert_eq!(outcome.status, "completed", "{outcome:#?}");
    assert_eq!(outcome.exit_code, 0);
    let invocations = invocations_for(log, root.path());
    assert_eq!(invocations.len(), 2, "{invocations:#?}");
    assert!(!invocations[0].contains("--hir-mode"));
    assert!(invocations[1].contains("--hir-mode syntax-only"));

    let fallback = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "rust-hir-syntax-only-fallback")
        .expect("syntax-only fallback diagnostic");
    assert_eq!(fallback.severity, "warning");
    assert!(fallback.message.contains("max_worker_memory_bytes"));
    assert!(fallback.message.contains(&MEMORY_BUDGET_BYTES.to_string()));
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "worker-failure")
    );
    assert!(
        outcome
            .coverage
            .reasons
            .iter()
            .any(|reason| reason == "rust-hir-memory-budget"),
        "{:?}",
        outcome.coverage.reasons
    );
    let analysis = outcome.analysis.expect("analysis progress");
    let rust_unit = analysis
        .units
        .iter()
        .find(|unit| unit.adapter == "rust")
        .expect("rust analysis unit");
    assert_eq!(rust_unit.status, "completed");
    assert_eq!(
        rust_unit.loader.get("rust_hir_mode").map(String::as_str),
        Some("syntax-only")
    );
    assert_eq!(
        rust_unit
            .loader
            .get("rust_hir_mode_reason")
            .map(String::as_str),
        Some("memory-limit")
    );
    Ok(())
}

#[tokio::test]
async fn rust_syntax_only_retry_that_also_fails_keeps_the_scan_partial() -> Result<()> {
    let log = install_worker();
    let root = rust_root(true);
    let store_dir = tempfile::tempdir()?;
    let mut store = Store::open(store_dir.path().join("graph.db"))?;
    let config = Config::load(root.path())?;

    let outcome = run_scan_with_cache_mode(
        &mut store,
        root.path().to_path_buf(),
        &config,
        false,
        ScanCacheMode::Disabled,
    )
    .await?;

    assert_eq!(outcome.status, "partial", "{outcome:#?}");
    assert_eq!(outcome.exit_code, 3);
    let invocations = invocations_for(log, root.path());
    assert_eq!(invocations.len(), 2, "{invocations:#?}");
    assert!(invocations[1].contains("--hir-mode syntax-only"));
    assert!(outcome.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "worker-failure" && diagnostic.message.contains("memory")
    }));
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "rust-hir-syntax-only-fallback")
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "rust-hir-syntax-only-fallback-failed")
    );
    Ok(())
}

#[tokio::test]
async fn failed_syntax_only_retry_keeps_the_full_mode_prefix_in_the_partial_scan() -> Result<()> {
    let log = install_worker();
    let root = rust_root_with(true, true);
    let store_dir = tempfile::tempdir()?;
    let mut store = Store::open(store_dir.path().join("graph.db"))?;
    let config = Config::load(root.path())?;

    let outcome = run_scan_with_cache_mode(
        &mut store,
        root.path().to_path_buf(),
        &config,
        false,
        ScanCacheMode::Disabled,
    )
    .await?;

    assert_eq!(outcome.status, "partial", "{outcome:#?}");
    let invocations = invocations_for(log, root.path());
    assert_eq!(invocations.len(), 2, "{invocations:#?}");
    assert!(invocations[1].contains("--hir-mode syntax-only"));
    // The retry failed before emitting anything, so the partial Rust graph
    // must still be the full-mode attempt's prefix.
    assert!(
        store
            .load_scan_profile_declaration(&outcome.scan_id, FULL_MODE_PROFILE_ID)?
            .is_some(),
        "{outcome:#?}"
    );
    let worker_failures = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "worker-failure")
        .count();
    assert_eq!(worker_failures, 1, "{:#?}", outcome.diagnostics);
    let fallback_failures = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "rust-hir-syntax-only-fallback-failed")
        .count();
    assert_eq!(fallback_failures, 1, "{:#?}", outcome.diagnostics);
    let analysis = outcome.analysis.expect("analysis progress");
    let rust_unit = analysis
        .units
        .iter()
        .find(|unit| unit.adapter == "rust")
        .expect("rust analysis unit");
    assert_eq!(rust_unit.status, "failed");
    assert_eq!(rust_unit.failure_reason.as_deref(), Some("memory-limit"));
    assert_eq!(rust_unit.loader.get("rust_hir_mode"), None);
    assert_eq!(
        rust_unit
            .loader
            .get("rust_hir_syntax_only_retry")
            .map(String::as_str),
        Some("failed")
    );
    Ok(())
}

#[tokio::test]
async fn syntax_only_retry_progress_keeps_the_other_units_of_a_mixed_scan() -> Result<()> {
    install_worker();
    let root = rust_root(false);
    fs::write(
        root.path().join("package.json"),
        r#"{"name":"memory-fallback-web","version":"0.1.0"}"#,
    )?;
    fs::write(root.path().join("index.js"), "export const value = 1;\n")?;
    let store_dir = tempfile::tempdir()?;
    let mut store = Store::open(store_dir.path().join("graph.db"))?;
    let config = Config::load(root.path())?;
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
    assert!(
        analysis
            .units
            .iter()
            .any(|unit| unit.adapter == "web" && unit.status == "completed"),
        "{analysis:#?}"
    );
    let observed = observer.snapshot();
    assert_eq!(
        observed
            .units
            .iter()
            .map(|unit| (unit.unit_id.as_str(), unit.status.as_str()))
            .collect::<Vec<_>>(),
        analysis
            .units
            .iter()
            .map(|unit| (unit.unit_id.as_str(), unit.status.as_str()))
            .collect::<Vec<_>>(),
    );
    let rust_unit = observed
        .units
        .iter()
        .find(|unit| unit.adapter == "rust")
        .expect("observed rust unit");
    assert_eq!(
        rust_unit.loader.get("rust_hir_mode").map(String::as_str),
        Some("syntax-only")
    );
    Ok(())
}
