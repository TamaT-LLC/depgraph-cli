//! Safe, static Rust adapter for the depgraph v1 protocol.
//!
//! The scanner deliberately limits Cargo invocation to `cargo metadata
//! --frozen --offline --no-deps`. Source, manifests, build scripts, and
//! procedural macros from the scanned repository are never executed.

mod emit;
mod manifest;
mod metadata;
mod scanner;
mod source;

pub use emit::build_events;
pub use scanner::{FileCoverage, ScanResult, scan};

pub const ADAPTER: &str = "rust";
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const EXTRACTOR: &str = "rust-static";
pub const RUST_TOOLCHAIN_BASELINE: &str = "1.93.1";
pub const RUST_HIR_INTEGRATION_POLICY: &str = "pinned-rust-analyzer-library";
