pub mod cli;
pub mod config;
pub mod graph;
pub mod model;
pub mod report;

pub use cli::{Command, Options};
pub use config::{OutputFormat, ProjectConfig};
pub use graph::{DependencyGraph, GraphBuilder};
pub use model::{Dependency, Module, ModuleId, ModuleKind, ScanSummary};
pub use report::{Report, ReportWriter};
