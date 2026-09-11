//! Opt-in timings for store phases, using the scan profiling flag.

use std::time::Instant;

use anyhow::Result;

pub(crate) fn run<T>(phase: &str, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let started = (std::env::var("DEPGRAPH_SCAN_PROFILE").as_deref() == Ok("1")).then(|| {
        eprintln!("depgraph-progress phase={phase} status=started");
        Instant::now()
    });
    let result = operation();
    if let Some(started) = started {
        let status = if result.is_ok() {
            "completed"
        } else {
            "failed"
        };
        eprintln!(
            "depgraph-progress phase={phase} status={status} duration_ms={}",
            started.elapsed().as_millis()
        );
    }
    result
}
