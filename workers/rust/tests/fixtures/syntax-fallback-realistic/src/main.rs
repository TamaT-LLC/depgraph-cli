use anyhow::Result;
use syntax_fallback_realistic::{GraphBuilder, Options, ProjectConfig, ReportWriter};

fn main() -> Result<()> {
    let options = Options::parse();
    let config = ProjectConfig::load(&options.config)?;
    let graph = GraphBuilder::new(config.clone()).scan(&options.root)?;
    ReportWriter::new(config.output.clone()).write(&graph)?;
    Ok(())
}
