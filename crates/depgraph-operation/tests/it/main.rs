//! depgraph-operation integration tests, built as one test binary.
//!
//! `process` stays a separate binary: it re-runs its own test executable with
//! `--exact launcher_server_helper` as a helper process.

mod journal;
mod manager;
mod runner;
