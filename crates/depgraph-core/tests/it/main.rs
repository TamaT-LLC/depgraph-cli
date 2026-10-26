//! depgraph-core integration tests, built as one test binary.
//!
//! `analysis_resplit_progress` and `rust_memory_fallback` stay separate
//! binaries: each installs a fake worker through `DEPGRAPH_*_WORKER` in the
//! process environment, which would leak into every other test here.

mod agent_import_groups;
mod analysis_split_contract;
mod health_range;
mod health_scan_fixtures;
mod import_evidence;
mod service;
mod service_artifacts;
mod service_bounded;
mod service_graph;
mod service_health;
mod service_repository_write;
mod service_store_write;
