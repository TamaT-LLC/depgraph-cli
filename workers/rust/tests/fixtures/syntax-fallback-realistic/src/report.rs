use crate::config::OutputFormat;
use crate::graph::DependencyGraph;
use crate::model::{Module, ModuleId, ScanSummary};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{self, Write};

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub summary: ScanSummary,
    pub modules: BTreeMap<ModuleId, Module>,
    pub diagnostics: Vec<String>,
}

impl From<&DependencyGraph> for Report {
    fn from(graph: &DependencyGraph) -> Self {
        Self {
            summary: graph.summary.clone(),
            modules: graph.modules.clone(),
            diagnostics: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReportWriter {
    format: OutputFormat,
}

impl ReportWriter {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    pub fn write(&self, graph: &DependencyGraph) -> Result<()> {
        let report = Report::from(graph);
        let rendered = match self.format {
            OutputFormat::Human => format!(
                "{} modules, {} dependencies",
                report.summary.modules, report.summary.dependencies
            ),
            OutputFormat::Json => serde_json::to_string_pretty(&report).context("render JSON")?,
            OutputFormat::Dot => "digraph dependencies {}".to_owned(),
        };
        writeln!(io::stdout().lock(), "{rendered}").context("write report")
    }
}
