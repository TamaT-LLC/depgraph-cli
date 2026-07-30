//! Safe, static Rust adapter for the depgraph v1 protocol.
//!
//! The scanner deliberately limits Cargo invocation to `cargo metadata
//! --frozen --offline --no-deps` against a sanitized, worker-owned input
//! mirror. Source, manifests, build scripts, and procedural macros from the
//! scanned repository are never executed or passed directly to Cargo.

mod cargo_mirror;
mod emit;
mod hir_project;
pub mod hir_scaffold;
mod hir_semantic;
mod hir_sysroot;
mod manifest;
mod metadata;
mod repository_inventory;
mod scanner;
mod source;
mod toolchain;

pub use emit::build_events;
pub use scanner::{FileCoverage, ScanResult, scan, scan_with_inventory_file};

pub const ADAPTER: &str = "rust";
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const EXTRACTOR: &str = "rust-static";
pub const RUST_TOOLCHAIN_BASELINE: &str = "1.93.1";
pub const RUSTC_BASELINE_COMMIT: &str = "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf";
pub const CARGO_BASELINE_COMMIT: &str = "083ac5135f967fd9dc906ab057a2315861c7a80d";
pub const RUST_HIR_INTEGRATION_POLICY: &str = "pinned-rust-analyzer-library";
pub const RUST_SYSROOT_CONTRACT_VERSION: &str = "rust-src-data-tree-v1";
pub const RUST_SYSROOT_COMPONENT_VERSION: &str =
    "1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf";
pub const RUST_SYSROOT_SOURCE_LAYOUT: &str = "rustup-rust-src-library-v1";
pub const RUST_SYSROOT_LICENSE_EXPRESSION: &str = "MIT OR Apache-2.0";
pub const RUST_ANALYZER_CRATE_VERSION: &str = "0.0.330";
pub const RUST_ANALYZER_REVISION: &str = "8954b66d43225e62c92e8bbcc8500191b5cceb1e";
pub const RUST_ANALYZER_SALSA_VERSION: &str = "0.26.1";
